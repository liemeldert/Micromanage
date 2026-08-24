"use client";

import {Stack} from "@mantine/core";
import {PageHeader} from "@/components/layout/PageHeader";
import {AlertBoard} from "@/components/dispatcher/AlertBoard";

export default function ComplianceAlertsPage() {
    return (
        <Stack gap="md">
            <PageHeader
                title="Alerts"
                description={<>Where the fleet has drifted from what the rules ask for. Alerts rank black, red, yellow,
                    green, worst first, and close themselves once the device is compliant again. Rules decide what is
                    raised here; they live under <b>Compliance &rarr; Rules</b>.</>}
            />
            <AlertBoard/>
        </Stack>
    );
}
