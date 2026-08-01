export function VulnerabilitiesPage() {
  return (
    <section className="space-y-2">
      <p className="text-sm font-medium text-muted-foreground">Security</p>
      <h1 className="text-3xl font-bold tracking-tight">Vulnerabilities</h1>
      <p className="max-w-2xl text-muted-foreground">
        CVE and patch-compliance reporting lands here once a patch-management provider
        (Jamf or LoonSecIO) is configured on a connection in Settings.
      </p>
    </section>
  );
}
