package snapshot

import (
	"slices"
	"strings"
	"testing"

	"github.com/chrisleekr/edge-proxy/internal/expr"
)

func withVariants(c *Config, v ...Variant) {
	r := c.Global.Responses["rate_limited_json"]
	r.Variants = v
	c.Global.Responses["rate_limited_json"] = r
}

func TestCompileRejectsVariants(t *testing.T) {
	const p = `global.responses["rate_limited_json"]`
	html := Variant{ContentType: "text/html; charset=utf-8", Body: "<p>{{retry_after}}"}
	runRejects(t, []rejectCase{
		{"variant with an unknown content type", func(c *Config) { withVariants(c, Variant{ContentType: "image/png", Body: "x"}) }, nil, p + ".variants[0].content_type", "must be one of"},
		{"variant repeating another variant's content type", func(c *Config) { withVariants(c, html, html) }, nil, p + ".variants[1].content_type", "already a body"},
		{"variant repeating the default's content type", func(c *Config) {
			withVariants(c, Variant{ContentType: "application/json", Body: "{}"})
		}, nil, p + ".variants[0].content_type", "already a body"},
		{"variant with an unclosed placeholder", func(c *Config) {
			withVariants(c, Variant{ContentType: "application/problem+json", Body: "{{retry_after"})
		}, nil, p + ".variants[0].body", `has no closing "}}"`},
		{"more variants than other content types", func(c *Config) {
			withVariants(c, html, html, html, html)
		}, nil, p + ".variants", "at most 3"},
		{"JSON variant with a bare word", func(c *Config) {
			withVariants(c, Variant{ContentType: "application/problem+json", Body: "oops"})
		}, nil, p + ".variants[0].body", "not valid JSON"},
		{"variant with an unknown placeholder", func(c *Config) {
			withVariants(c, Variant{ContentType: "text/plain; charset=utf-8", Body: "{{nope}}"})
		}, nil, p + ".variants[0].body", "unknown placeholder {{nope}}"},
		{"default body with an unknown placeholder", func(c *Config) {
			r := c.Global.Responses["rate_limited_json"]
			r.Body = "{{nope}}"
			c.Global.Responses["rate_limited_json"] = r
		}, nil, p + ".body", "unknown placeholder {{nope}}"},
	})
}

func TestVariantsCompileDefaultFirst(t *testing.T) {
	c := validConfig()
	withVariants(c, Variant{ContentType: "text/html; charset=utf-8", Body: "<p>{{retry_after}}"}, Variant{ContentType: "text/plain; charset=utf-8", Body: "wait {{retry_after}}"})
	out, _, errs := Compile(c, testDeployment)
	if errs != nil {
		t.Fatal(expr.Issues(errs))
	}
	got := out.Responses["rate_limited_json"]
	var types, media []string
	for _, b := range got {
		types, media = append(types, b.ContentType), append(media, b.MediaType)
	}
	if want := []string{"application/json", "text/html; charset=utf-8", "text/plain; charset=utf-8"}; !slices.Equal(types, want) {
		t.Errorf("content types %v, want %v", types, want)
	}
	if want := []string{"application/json", "text/html", "text/plain"}; !slices.Equal(media, want) {
		t.Errorf("media types %v, want %v", media, want)
	}
	if len(out.Responses["rate_limited_html"]) != 1 {
		t.Errorf("a template without variants has %d bodies, want 1", len(out.Responses["rate_limited_html"]))
	}
}

// Variants need schema 14. A policy of any schema may set them and then needs
// edges that read schema 14.
func TestVariantsNeedSchema14Edges(t *testing.T) {
	cases := []struct {
		name     string
		variants bool
		want     int
	}{
		{"schema 9 policy without variants", false, 9},
		{"schema 9 policy with a variant", true, VariantsSchema},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			c.Schema = 9
			if tc.variants {
				withVariants(c, Variant{ContentType: "text/plain; charset=utf-8", Body: "x"})
			}
			got, _, errs := Compile(c, testDeployment)
			if errs != nil {
				t.Fatal(expr.Issues(errs))
			}
			if got.NeedsSchema != tc.want {
				t.Fatalf("needs schema %d, want %d", got.NeedsSchema, tc.want)
			}
		})
	}
}

func TestStarterHasDefaultBodiesForEveryKind(t *testing.T) {
	starter := Starter()
	starter.Version = 1
	out, warns, errs := Compile(starter, testDeployment)
	if errs != nil || len(warns) > 0 {
		t.Fatalf("errors %v, warnings %v", expr.Issues(errs), warns)
	}
	if out.NeedsSchema != VariantsSchema {
		t.Errorf("starter needs schema %d, want %d", out.NeedsSchema, VariantsSchema)
	}
	for kind := range statusOf {
		if _, ok := pageText[kind]; !ok {
			t.Errorf("pageText has no entry for %s", kind)
		}
		var types []string
		for _, b := range out.Responses[kind] {
			types = append(types, b.ContentType)
		}
		if want := []string{"application/problem+json", "text/html; charset=utf-8", "text/plain; charset=utf-8"}; !slices.Equal(types, want) {
			t.Errorf("%s bodies %v, want %v", kind, types, want)
		}
	}
	if len(pageText) != len(statusOf) {
		t.Errorf("pageText has %d kinds, want %d", len(pageText), len(statusOf))
	}
}

func TestSampleBody(t *testing.T) {
	cases := []struct {
		name, ct, body, want, err string
	}{
		{"status is the template's own", "application/json", `{"s":{{status}}}`, `{"s":503}`, ""},
		{"retry_after and request_id get sample values", "text/plain; charset=utf-8", "{{retry_after}} {{request_id}}", "1 r1", ""},
		{"unknown placeholder", "text/plain; charset=utf-8", "{{nope}}", "", "unknown placeholder {{nope}}"},
		{"JSON that is not JSON", "application/json", "x", "", "not valid JSON"},
		{"body over the limit", "text/plain; charset=utf-8", strings.Repeat("a", MaxBodyTemplate+1), "", "at most"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SampleBody(503, tc.ct, tc.body)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("error %v, want one containing %q", err, tc.err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}
