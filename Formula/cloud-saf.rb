# Homebrew formula for CSAF (distribution name: cloud-saf).
# Until a tagged tarball exists, install from HEAD:
#   brew install --HEAD Formula/cloud-saf.rb
class CloudSaf < Formula
  desc "Read-only multi-cloud security posture assessment (AWS, Azure, GCP, Kubernetes)"
  homepage "https://github.com/rikterskale/Cloud-Security-Assessment-Framework"
  license "MIT"
  head "https://github.com/rikterskale/Cloud-Security-Assessment-Framework.git", branch: "main"

  depends_on "python@3.12"

  def install
    virtualenv_install_with_resources
  end

  test do
    output = shell_output("#{bin}/csaf-assess --version")
    assert_match "CSAF v", output
  end
end
