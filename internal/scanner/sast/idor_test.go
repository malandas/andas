package sast

import "testing"

func TestDetectIDOR(t *testing.T) {
	vuln := []string{"app.get('/o/:id', (req,res)=>{", "  Order.findById(req.params.id)", "  res.json(o)", "})"}
	if !detectIDOR(vuln, 1) {
		t.Error("by-id lookup with no ownership check should be flagged IDOR")
	}
	safe := []string{"app.get('/o/:id', (req,res)=>{", "  const o = Order.findById(req.params.id)", "  if (o.user_id !== req.user.id) return deny()", "})"}
	if detectIDOR(safe, 1) {
		t.Error("a lookup with a nearby ownership check must NOT be IDOR")
	}
	if detectIDOR([]string{"const x = 1"}, 0) {
		t.Error("a non-lookup line must not be IDOR")
	}
}
