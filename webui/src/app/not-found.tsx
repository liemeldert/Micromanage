import Link from "next/link";
import {Button, Paper, Stack, Text, Title} from "@mantine/core";

export default function NotFound() {
    return (
        <Stack align="center" justify="center" mih="100vh" p="lg">
            <Paper withBorder p="xl" maw={440} w="100%">
                <Stack gap="md" align="center">
                    <Title order={3}>Page not found</Title>
                    <Text fz="sm" c="dimmed" ta="center">
                        Nothing lives at this address.
                    </Text>
                    <Link href="/dashboard" style={{textDecoration: "none"}}>
                        <Button>Back to dashboard</Button>
                    </Link>
                </Stack>
            </Paper>
        </Stack>
    );
}
