"""Virtual-machine compute controls (subscription scope)."""

from __future__ import annotations

from ...base import AssessmentModule, CheckContext

API_COMPUTE = "2024-03-01"


class ComputeModule(AssessmentModule):
    name = "compute"

    def vm_managed_disks(self, control, ctx: CheckContext):
        arm = ctx.session
        sub = f"/subscriptions/{ctx.account_id}"
        vms = arm.get_value(f"{sub}/providers/Microsoft.Compute/virtualMachines", API_COMPUTE)
        if not vms:
            return self.result(control, ctx, "NotApplicable", "No virtual machines in subscription.")
        offenders = []
        for vm in vms:
            profile = vm.get("properties", {}).get("storageProfile", {})
            disks = [profile.get("osDisk", {})] + list(profile.get("dataDisks", []))
            if any(d.get("vhd") for d in disks):
                offenders.append(vm.get("name", "unknown"))
        if not offenders:
            return self.result(control, ctx, "Pass", f"All {len(vms)} VM(s) use managed disks.")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"VM uses unmanaged (VHD) disks: {name}",
                resource_type="virtual-machine",
                resource_id=name,
            )
            for name in offenders
        ]
