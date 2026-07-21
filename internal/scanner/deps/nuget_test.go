package deps

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNugetCollect(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "App.csproj"), []byte(
		`<Project><ItemGroup>
  <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
  <PackageReference Version="2.10.0" Include="Serilog" />
  <PackageReference Include="ManagedCentrally" />
</ItemGroup></Project>`), 0o644)
	os.WriteFile(filepath.Join(dir, "Directory.Packages.props"), []byte(
		`<Project><ItemGroup>
  <PackageVersion Include="System.Text.Json" Version="4.7.0" />
</ItemGroup></Project>`), 0o644)

	refs := nugetCollect(dir)
	got := map[string]string{}
	for _, r := range refs {
		if r.Ecosystem != "NuGet" {
			t.Errorf("%s: ecosystem = %q, want NuGet", r.Name, r.Ecosystem)
		}
		got[r.Name] = r.Version
	}
	want := map[string]string{"Newtonsoft.Json": "12.0.1", "Serilog": "2.10.0", "System.Text.Json": "4.7.0"}
	for n, v := range want {
		if got[n] != v {
			t.Errorf("%s: got version %q, want %q", n, got[n], v)
		}
	}
	// A version-less (centrally-managed) reference must not appear without a version.
	if _, ok := got["ManagedCentrally"]; ok {
		t.Error("a PackageReference with no Version should be skipped (version comes from props)")
	}
}
