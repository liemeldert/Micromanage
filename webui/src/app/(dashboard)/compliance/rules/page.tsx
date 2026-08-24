"use client";

import {Suspense} from "react";
import {useSearchParams} from "next/navigation";
import {Stack} from "@mantine/core";
import {PageHeader} from "@/components/layout/PageHeader";
import {RuleEditor} from "@/components/dispatcher/RuleEditor";

export default function ComplianceRulesPage() {
    return (
        <Stack gap="md">
            <PageHeader
                description={<>
                    What counts as a deviation, and what happens when one turns up. A rule can raise an
                    alert, post to a signed webhook, or run a quick triage action. This is the Dispatch
                    engine; what it raises shows up under <b>Compliance → Alerts</b>.
                </>}
            />
            {/* useSearchParams requires a Suspense boundary during prerender. */}
            <Suspense fallback={null}>
                <DeepLinkedRuleEditor/>
            </Suspense>
        </Stack>
    );
}

// ?rule=<id> comes from the alert board and opens that rule selected. An id nothing matches is ignored.
function DeepLinkedRuleEditor() {
    const searchParams = useSearchParams();
    return <RuleEditor initialRuleId={searchParams.get("rule")}/>;
}
