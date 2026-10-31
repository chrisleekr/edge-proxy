package admin

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/chrisleekr/edge-proxy/internal/admindb"
	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// exclusion is one autopilot_exclusions row: a client a person found
// legitimate on a host, and optionally a path prefix. Every autopilot rule
// proposed while it is active leaves that traffic out. No model tool can
// make or end one.
type exclusion struct {
	ID           int64        `json:"id"`
	Subject      netip.Prefix `json:"subject"`
	Host         string       `json:"host"`
	PathPrefix   string       `json:"path_prefix"`
	Reason       string       `json:"reason"`
	RuleID       *string      `json:"rule_id"`
	CreatedBy    string       `json:"created_by"`
	CreatedAt    time.Time    `json:"created_at"`
	ExpiresAt    *time.Time   `json:"expires_at"`
	RevokedAt    *time.Time   `json:"revoked_at"`
	RevokedBy    *string      `json:"revoked_by"`
	RevokeReason *string      `json:"revoke_reason"`
}

const exclusionCols = "id, subject, host, path_prefix, reason, rule_id, created_by, created_at, expires_at, revoked_at, revoked_by, revoke_reason"

func activeExclusions(ctx context.Context, q querier, now time.Time) ([]exclusion, error) {
	rows, err := q.Query(ctx, "SELECT "+exclusionCols+" FROM autopilot_exclusions WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > $1) ORDER BY id", now)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[exclusion])
}

// exclusionNode is the condition that leaves the exclusions' traffic out:
// not any of (client and host and path prefix).
func exclusionNode(ex []exclusion) (expr.Node, bool) {
	var each []expr.Node
	for _, e := range ex {
		and := []expr.Node{
			{Field: "ip.src", Operator: "in", Value: expr.Value{List: []string{e.Subject.String()}, IsList: true}},
			{Field: "http.host", Operator: "eq", Value: expr.Value{One: e.Host}},
		}
		if e.PathPrefix != "" {
			and = append(and, expr.Node{Field: "http.request.uri.path", Operator: "starts_with", Value: expr.Value{One: e.PathPrefix}})
		}
		each = append(each, expr.Node{Combinator: "and", Rules: and})
	}
	return expr.Node{Combinator: "or", Not: true, Rules: each}, each != nil
}

// scopeOf is the host and path prefix a rule's and groups fix: what an
// exclusion promoted from it narrows to. Not groups, which is how
// exclusions are carried, are skipped.
func scopeOf(n expr.Node) (host, prefix string) {
	if !n.IsGroup() {
		switch {
		case n.Field == "http.host" && n.Operator == "eq":
			return n.Value.One, ""
		case n.Field == "http.request.uri.path" && n.Operator == "starts_with":
			return "", n.Value.One
		}
		return "", ""
	}
	if n.Combinator != "and" || n.Not {
		return "", ""
	}
	for _, r := range n.Rules {
		h, p := scopeOf(r)
		host, prefix = cmp.Or(host, h), cmp.Or(prefix, p)
	}
	return host, prefix
}

// addExclusion is POST /api/autopilot/exclusions. With rule_id naming a
// live sensor, host and path_prefix default to the sensor's, and the
// sensor is retired in the same transaction, so the next sweep can watch
// the route again with the client left out.
func (s *Server) addExclusion(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in struct {
		Subject    string             `json:"subject"`
		Host       string             `json:"host"`
		PathPrefix string             `json:"path_prefix"`
		Reason     string             `json:"reason"`
		TTL        *snapshot.Duration `json:"ttl"`
		RuleID     string             `json:"rule_id"`
	}
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	ctx := r.Context()
	var out exclusion
	err := s.autopilotTx(ctx, func(tx pgx.Tx) error {
		now := s.now()
		var errs []expr.Issue
		add := func(path, msg string) { errs = append(errs, expr.Issue{Path: path, Msg: msg}) }
		invalid := func() error {
			return &problem{Status: http.StatusUnprocessableEntity, Title: "Invalid exclusion", Errors: errs}
		}
		var src *apRule
		if in.RuleID != "" {
			rules, err := s.loadRules(ctx, tx, "id = $1 AND kind = 'sensor' AND state IN ('proposed', 'observing')", in.RuleID)
			if err != nil {
				return err
			}
			if len(rules) != 1 {
				add("rule_id", "must name a proposed or observing autopilot sensor")
			} else {
				src = &rules[0]
				h, pre := scopeOf(src.Rule.Expression)
				in.Host, in.PathPrefix = cmp.Or(in.Host, h), cmp.Or(in.PathPrefix, pre)
			}
		}
		pre, _, ok := parseSubject(in.Subject)
		// Judge the width the edge applies: it matches ::ffff:a.b.c.d/n as a.b.c.d/(n-96).
		if ok && pre.Addr().Is4In6() {
			if pre.Bits() >= 96 {
				pre = netip.PrefixFrom(pre.Addr().Unmap(), pre.Bits()-96)
			} else {
				ok = false
			}
		}
		// A scoped exclusion names a client; a wider network belongs in
		// protected_subjects.
		if !ok || !pre.IsValid() || pre.Addr().Is4() && pre.Bits() < 24 || pre.Addr().Is6() && pre.Bits() < 48 {
			add("subject", "must be an IP, or a CIDR of at least /24 for IPv4 or /48 for IPv6")
		}
		if in.Host == "" {
			add("host", "is required")
		}
		if in.PathPrefix != "" && !strings.HasPrefix(in.PathPrefix, "/") {
			add("path_prefix", "must start with /")
		}
		in.Reason = strings.TrimSpace(in.Reason)
		if in.Reason == "" || utf8.RuneCountInString(in.Reason) > 500 {
			add("reason", "is required, at most 500 characters")
		}
		if in.TTL != nil && (time.Duration(*in.TTL) < time.Hour || time.Duration(*in.TTL) > 365*24*time.Hour) {
			add("ttl", "must be 1h to 8760h, or left out for no expiry")
		}
		if errs != nil {
			return invalid()
		}
		set, err := loadAutopilot(ctx, tx)
		if err != nil {
			return err
		}
		ex, err := activeExclusions(ctx, tx, now)
		if err != nil {
			return err
		}
		out = exclusion{Subject: pre, Host: in.Host, PathPrefix: in.PathPrefix, Reason: in.Reason, CreatedBy: p.actor, CreatedAt: now}
		if in.TTL != nil {
			exp := now.Add(time.Duration(*in.TTL)).Truncate(time.Second)
			out.ExpiresAt = &exp
		}
		node, _ := exclusionNode([]exclusion{out})
		// The values are checked as the edge checks them in a rule.
		for _, is := range expr.Check(node, expr.Env{Phase: expr.PhaseRateLimit, AllowRegex: s.cfg.Deployment.AllowRegex}) {
			add("expression", is.Msg)
		}
		// Every autopilot rule carries the exclusions with the protected
		// networks; they share half an expression, as protected_subjects
		// alone does, which also bounds how many there can be.
		all, _ := exclusionNode(append(slices.Clone(ex), out))
		used := len(expr.Render(all))
		if pn, ok := protectedExclusion(set); ok {
			used += len(expr.Render(pn))
		}
		if used > expr.MaxTextLen/2 {
			add("subject", fmt.Sprintf("%d exclusions take %d characters of every autopilot rule's expression with the protected networks, over %d; revoke some first",
				len(ex)+1, used, expr.MaxTextLen/2))
		}
		if errs != nil {
			return invalid()
		}
		if src != nil {
			out.RuleID = &src.ID
		}
		if err := tx.QueryRow(ctx, `INSERT INTO autopilot_exclusions (subject, host, path_prefix, reason, rule_id, created_by, created_at, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`, out.Subject, out.Host, out.PathPrefix, out.Reason, out.RuleID, out.CreatedBy, now, out.ExpiresAt).Scan(&out.ID); err != nil {
			return err
		}
		if src != nil {
			if err := s.applyChanges(ctx, tx, []ruleChange{{from: src.State, next: ended(*src, "retired", "retired", now),
				reason: fmt.Sprintf("its traffic from %s was excluded (exclusion %d)", out.Subject, out.ID), actor: p.actor, action: "autopilot.retire",
				numbers: map[string]any{"exclusion": out.ID}}}, nil); err != nil {
				return err
			}
		}
		return admindb.Audit(ctx, tx, s.cfg.Audit, s.now, admindb.Event{Actor: p.actor, Action: "autopilot.exclusion_add", Target: fmt.Sprintf("exclusion %d", out.ID),
			Details: map[string]any{"subject": out.Subject.String(), "host": out.Host, "path_prefix": out.PathPrefix, "reason": out.Reason, "expires_at": out.ExpiresAt, "rule": out.RuleID}})
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusCreated, out)
}

// revokeExclusion is POST /api/autopilot/exclusions/{id}/revoke. Rules
// proposed after it no longer leave the client out, and the next tick
// retires the sensors that still do.
func (s *Server) revokeExclusion(w http.ResponseWriter, r *http.Request, p *principal) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	var in struct {
		Reason string `json:"reason"`
	}
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	if in.Reason = strings.TrimSpace(in.Reason); in.Reason == "" || utf8.RuneCountInString(in.Reason) > 500 {
		return &problem{Status: http.StatusUnprocessableEntity, Title: "Invalid revoke", Errors: []expr.Issue{{Path: "reason", Msg: "is required, at most 500 characters"}}}
	}
	ctx := r.Context()
	err = s.autopilotTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE autopilot_exclusions SET revoked_at = $2, revoked_by = $3, revoke_reason = $4 WHERE id = $1 AND revoked_at IS NULL",
			id, s.now(), p.actor, in.Reason)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fail(http.StatusConflict, fmt.Sprintf("exclusion %d does not exist or is revoked already", id))
		}
		return admindb.Audit(ctx, tx, s.cfg.Audit, s.now, admindb.Event{Actor: p.actor, Action: "autopilot.exclusion_revoke", Target: fmt.Sprintf("exclusion %d", id),
			Details: map[string]any{"reason": in.Reason}})
	})
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// listExclusions is GET /api/autopilot/exclusions: the active ones, and
// those that ended in the last 30 days, newest first.
func (s *Server) listExclusions(w http.ResponseWriter, r *http.Request, _ *principal) error {
	rows, err := s.db.Query(r.Context(), "SELECT "+exclusionCols+` FROM autopilot_exclusions
		WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > $1) OR revoked_at > $1 ORDER BY id DESC LIMIT 200`, s.now().Add(-30*24*time.Hour))
	if err != nil {
		return err
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[exclusion])
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, orEmpty(list))
}
