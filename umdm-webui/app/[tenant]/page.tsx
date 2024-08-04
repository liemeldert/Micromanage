'use client';
import {Box, Button, Code, Heading, Text} from "@chakra-ui/react";
import React from "react";
import {useTenant} from "@/lib/useTenant";


export default function Home() {
    const tenant = useTenant();
    const domain = window.location.hostname;

    const [webhookUrl, setWebhookUrl] = React.useState<string | null>(null);

    // useEffect(() => {
    //     if (tenant.loading) {
    //         setWebhookUrl("loading...");
    //     } else {
    //         if (tenant.tenant) {
    //             setWebhookUrl(`https://${domain}/${tenant.tenant._id}/webhook`)
    //         }
    //     }
    // });

    const handleWebhookGet = async () => {
        const response = await fetch(`/${tenant?.tenant?._id}/api/get_complete_tenant`);
        if (!response.ok) {
            throw new Error('Failed to fetch webhook URL');
        }
        const data = await response.json();
        setWebhookUrl(`https://${domain}/${data._id}/webhook/${data.webhook_secret}`);
    }


    return (
        <Box>
            <Heading>Welcome to uMDM</Heading>
            <Text>This will be a dashboard in a future version.</Text>

            <Heading mt={"5rem"}>Setup information</Heading>
            <Text>In order to receive device status information, you must configure the webhook_url on your MicroMDM
                server to the following:</Text>

            <Button onClick={handleWebhookGet} mr={"4"}>Show URL</Button>
            <Code>{webhookUrl}</Code>

        </Box>
    );
}
