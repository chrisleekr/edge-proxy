package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/chrisleekr/edge-proxy/internal/admindb"
	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// AutopilotSettings bound what the autopilot may do. Mode off removes its
// rules; observe proposes and measures, and a person approves enforcing;
// auto enforces once the measurements hold.
type AutopilotSettings struct {
	Mode               string            `json:"mode"`
	MaxEnforcing       int               `json:"max_enforcing"`
	MaxSensors         int               `json:"max_sensors"`
	ObserveFor         snapshot.Duration `json:"observe_for"`
	DefaultTTL         snapshot.Duration `json:"default_ttl"`
	MaxTTL             snapshot.Duration `json:"max_ttl"`
	MaxLifetime        snapshot.Duration `json:"max_lifetime"`
	MaxBlockShare      float64           `json:"max_block_share"`
	CasesPerHour       int               `json:"cases_per_hour"`
	MinPublishInterval snapshot.Duration `json:"min_publish_interval"`
	Model              string            `json:"model"`
	SweepModel         string            `json:"sweep_model"`
	// ProtectedSubjects are CIDRs and AS numbers (AS64500) no autopilot
	// rule may block. They restrict the autopilot only: they are not an edge
	// exemption.
	ProtectedSubjects []string `json:"protected_subjects"`
}

func defaultAutopilot() AutopilotSettings {
	m := snapshot.Duration(time.Minute)
	return AutopilotSettings{
		Mode: "auto", MaxEnforcing: 10, MaxSensors: 10, ObserveFor: 5 * m, DefaultTTL: 60 * m, MaxTTL: snapshot.Duration(maxOverlayTTL),
		MaxLifetime: 7 * 24 * 60 * m, MaxBlockShare: 0.02, CasesPerHour: 20, MinPublishInterval: m,
		Model: "claude-opus-5-5", SweepModel: "claude-opus-5-5", ProtectedSubjects: []string{},
	}
}

var modelID = regexp.MustCompile(`^[A-Za-z0-9._:/@-]{1,100}$`)

// maxProtectedSubjects bounds the list checked on every enforce.
const maxProtectedSubjects = 200

// minRenewableTTL is the shortest TTL a rule can be renewed within: it
// renews in its last quarter, on a tick that publishes only
// min_publish_interval after the last autopilot publish.
func (a AutopilotSettings) minRenewableTTL() time.Duration {
	return 4 * (autopilotEvery + time.Duration(a.MinPublishInterval))
}

func (a AutopilotSettings) problems() []expr.Issue {
	var errs []expr.Issue
	add := func(p, m string) { errs = append(errs, expr.Issue{Path: p, Msg: m}) }
	d := func(v snapshot.Duration) time.Duration { return time.Duration(v) }
	publishOK := d(a.MinPublishInterval) >= 30*time.Second && d(a.MinPublishInterval) <= 15*time.Minute
	renewable := func(field string, v snapshot.Duration) {
		if publishOK && d(v) < a.minRenewableTTL() {
			add(field, fmt.Sprintf("must be at least %s, 4 times a %s tick plus min_publish_interval: a rule renews in the last quarter of its ttl", a.minRenewableTTL(), autopilotEvery))
		}
	}
	if a.Mode != "off" && a.Mode != "observe" && a.Mode != "auto" {
		add("mode", "must be off, observe or auto")
	}
	if a.MaxEnforcing < 0 || a.MaxEnforcing > 50 {
		add("max_enforcing", "must be 0 to 50")
	}
	if a.MaxSensors < 0 || a.MaxSensors > 50 {
		add("max_sensors", "must be 0 to 50")
	}
	if d(a.ObserveFor) < time.Minute || d(a.ObserveFor) > time.Hour {
		add("observe_for", "must be 1m to 1h")
	}
	if d(a.MaxTTL) < time.Minute || d(a.MaxTTL) > maxOverlayTTL {
		add("max_ttl", "must be 1m to 24h, the longest an autopilot rule may run before it is renewed")
	} else {
		renewable("max_ttl", a.MaxTTL)
	}
	if d(a.DefaultTTL) < time.Minute || a.DefaultTTL > a.MaxTTL {
		add("default_ttl", "must be from 1m to max_ttl")
	} else {
		renewable("default_ttl", a.DefaultTTL)
	}
	if a.MaxLifetime < a.MaxTTL || d(a.MaxLifetime) > 30*24*time.Hour {
		add("max_lifetime", "must be from max_ttl to 720h (30 days)")
	}
	if !(a.MaxBlockShare >= 0.001 && a.MaxBlockShare <= 0.2) {
		add("max_block_share", "must be 0.001 to 0.2 (0.1% to 20% of fleet requests)")
	}
	if a.CasesPerHour < 1 || a.CasesPerHour > 200 {
		add("cases_per_hour", "must be 1 to 200")
	}
	if !publishOK {
		add("min_publish_interval", "must be 30s to 15m")
	}
	if !modelID.MatchString(a.Model) {
		add("model", "must be a model id of 1 to 100 letters, digits and ._:/@-")
	}
	if !modelID.MatchString(a.SweepModel) {
		add("sweep_model", "must be a model id of 1 to 100 letters, digits and ._:/@-")
	}
	if len(a.ProtectedSubjects) > maxProtectedSubjects {
		add("protected_subjects", fmt.Sprintf("at most %d subjects", maxProtectedSubjects))
	} else {
		for i, s := range a.ProtectedSubjects {
			if _, _, ok := parseSubject(s); !ok {
				add(fmt.Sprintf("protected_subjects[%d]", i), "must be an IP, a CIDR such as 203.0.113.0/24, or an AS number such as AS64500")
			}
		}
		// Every autopilot rule carries them in its expression, which needs
		// room for the model's own condition too.
		if n, ok := protectedExclusion(a); ok && len(expr.Render(n)) > expr.MaxTextLen/2 {
			add("protected_subjects", fmt.Sprintf("the networks take %d characters in every autopilot rule's expression, over %d; use fewer or wider CIDRs",
				len(expr.Render(n)), expr.MaxTextLen/2))
		}
	}
	return errs
}

// parseSubject reads a protected subject: a prefix (an IP is a /32 or
// /128), or an AS number.
func parseSubject(s string) (netip.Prefix, int64, bool) {
	if n, ok := strings.CutPrefix(strings.ToUpper(s), "AS"); ok {
		v, err := strconv.ParseInt(n, 10, 64)
		return netip.Prefix{}, v, err == nil && v > 0 && v <= math.MaxUint32
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), 0, true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), 0, true
	}
	return netip.Prefix{}, 0, false
}

// providerOf is the provider whose credential runs model: a Claude model
// id names claude; anything else runs on OpenAI.
func providerOf(model string) string {
	if strings.Contains(strings.ToLower(model), "claude") {
		return "claude"
	}
	return "openai"
}

func loadAutopilot(ctx context.Context, q querier) (AutopilotSettings, error) {
	a := defaultAutopilot()
	var b []byte
	err := q.QueryRow(ctx, "SELECT value FROM settings WHERE key = 'autopilot'").Scan(&b)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, nil
	}
	if err != nil {
		return a, err
	}
	err = json.Unmarshal(b, &a)
	if a.ProtectedSubjects == nil {
		a.ProtectedSubjects = []string{}
	}
	// Settings saved before the renewal minimum existed may be under it:
	// raised here, so an upgrade keeps the autopilot running. A save under
	// it is refused.
	floor := snapshot.Duration(a.minRenewableTTL())
	a.MaxTTL, a.DefaultTTL, a.MaxLifetime = max(a.MaxTTL, floor), max(a.DefaultTTL, floor), max(a.MaxLifetime, floor)
	return a, err
}

// autopilotTx runs fn holding the locks a publish takes, in its order: the
// draft row, then the publish lock. Autopilot state changes and their
// publish then commit together, or not at all.
func (s *Server) autopilotTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	// A rule change can retract notes, counted once this commits.
	return s.noteTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT 1 FROM config_draft FOR UPDATE"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", publishLock); err != nil {
			return err
		}
		return fn(tx)
	})
}

func (s *Server) autopilotSettingsRoutes() {
	s.handle("GET /api/settings/autopilot", "autopilot.read", func(w http.ResponseWriter, r *http.Request, _ *principal) error {
		a, err := loadAutopilot(r.Context(), s.db)
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, a)
	})
	s.handle("PUT /api/settings/autopilot", "settings.manage", s.putAutopilotSettings)
}

// putAutopilotSettings saves the settings. Turning the mode off is the kill
// switch: in the same transaction every autopilot rule is retired, every
// open case cancelled and the overlay published empty.
func (s *Server) putAutopilotSettings(w http.ResponseWriter, r *http.Request, p *principal) error {
	// Reason is why a person changed the settings, such as turning the
	// autopilot off. It goes into the audit row only.
	var in struct {
		AutopilotSettings
		Reason string `json:"reason"`
	}
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	a, reason := in.AutopilotSettings, strings.TrimSpace(in.Reason)
	if a.ProtectedSubjects == nil {
		a.ProtectedSubjects = []string{}
	}
	errs := a.problems()
	if utf8.RuneCountInString(reason) > 500 {
		errs = append(errs, expr.Issue{Path: "reason", Msg: "is at most 500 characters"})
	}
	if errs != nil {
		return &problem{Status: http.StatusUnprocessableEntity, Title: "Invalid autopilot settings", Errors: errs}
	}
	ctx := r.Context()
	var published *int64
	var cancelled []string
	err := s.autopilotTx(ctx, func(tx pgx.Tx) error {
		before, err := loadAutopilot(ctx, tx)
		if err != nil {
			return err
		}
		if a.Mode == "off" && before.Mode != "off" {
			if published, cancelled, err = s.killSwitch(ctx, tx, p); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO settings (key, value, updated_at) VALUES ('autopilot', $1, $2)
			ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = $2`, a, s.now()); err != nil {
			return err
		}
		details := map[string]any{"before": before, "after": a, "version": published}
		if reason != "" {
			details["reason"] = reason
		}
		return admindb.Audit(ctx, tx, s.cfg.Audit, s.now, admindb.Event{Actor: p.actor, Action: "settings.autopilot", Details: details})
	})
	if err != nil {
		return err
	}
	if published != nil {
		s.met.published("autopilot")
	}
	for _, kind := range cancelled {
		s.met.autopilot.caseClosed(kind, "cancelled")
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// killSwitch retires every autopilot rule, cancels open cases and, when the
// active version holds autopilot rules, publishes it without them. It
// returns the version published, if any, and the kinds of the cases it
// cancelled.
func (s *Server) killSwitch(ctx context.Context, tx pgx.Tx, p *principal) (*int64, []string, error) {
	c, err := loadCanary(ctx, tx)
	if err != nil {
		return nil, nil, err
	}
	if c != nil {
		return nil, nil, fail(http.StatusConflict, fmt.Sprintf("version %d is in canary; promote or abort it, then turn autopilot off", c.Version))
	}
	rules, err := s.loadRules(ctx, tx, "state IN ('proposed', 'observing', 'enforcing')")
	if err != nil {
		return nil, nil, err
	}
	now := s.now()
	var changes []ruleChange
	for _, ar := range rules {
		changes = append(changes, ruleChange{from: ar.State, next: ended(ar, "retired", "retired", now), reason: "kill_switch", actor: p.actor, action: "autopilot.retire"})
	}
	kinds, err := s.cancelCases(ctx, tx, p.actor, "state IN ('queued', 'running')", "autopilot was turned off")
	if err != nil {
		return nil, nil, err
	}
	var v *int64
	active, err := s.activeConfig(ctx, tx)
	if err != nil {
		return nil, nil, err
	}
	if active != nil && hasOverlay(active) {
		n, err := s.publishOverlayTx(ctx, tx, nil, "Autopilot turned off: remove its rules", true)
		if err != nil {
			return nil, nil, err
		}
		v = &n
	}
	return v, kinds, s.applyChanges(ctx, tx, changes, v)
}

// hasOverlay reports whether c holds any autopilot rule, expired or not.
func hasOverlay(c *snapshot.Config) bool {
	for _, r := range c.RateLimitRules {
		if isOverlay(r.ID) {
			return true
		}
	}
	return false
}
