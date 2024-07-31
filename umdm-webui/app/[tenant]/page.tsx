'use client';
import {Box, Code, Heading, Text} from "@chakra-ui/react";
import React from "react";
import {useTenant} from "@/lib/useTenant";


export default function Home() {
    const tenant = useTenant();
    const domain = window.location.hostname;

    const [ webhookUrl, setWebhookUrl ] = React.useState<string | null>(null);

    React.useEffect(() => {
        if (tenant.loading) {
            setWebhookUrl("Loading...");
        } else {
            const current_tenant = tenant.tenant;
            if (!current_tenant) {
                setWebhookUrl("No tenant selected somehow");
                return;
            }
            const url = `${current_tenant.mdm_url}/webhook/${current_tenant.webhook_secret}`;
            setWebhookUrl(url);
        }
    }, [useTenant]);


    return (
        <Box>
            <Heading>Welcome to uMDM</Heading>
            <Text>This will be a dashboard in a future version.</Text>

            <Heading mt={"5rem"}>Setup information</Heading>
            <Text>In order to receive device status information, you must configure the webhook_url on your MicroMDM
                server to the following:</Text>
            <Code>{webhookUrl}</Code>

        </Box>
    );
}
