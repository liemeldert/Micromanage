"use client"

import {Box, Card, Center, Divider, Heading} from "@chakra-ui/react";
import Logo from "@/app/components/branding";
import React from "react";
import {useSession} from "next-auth/react";
import {useRouter} from "next/navigation";
import TenantForm from "@/app/tenant-create/tenant-form";

export default function TenantSelect() {
    const [allowedTenants, setAllowedTenants] = React.useState([]);
    const [loading, setLoading] = React.useState(true);
    const [error, setError] = React.useState("");

    const {data: session, status} = useSession();
    const router = useRouter();

    if (status === "loading") {
        return <p>Loading...</p>
    }

    if (status === "unauthenticated") {
        router.push("/auth/login")
        return <p>Not authenticated</p>
    }

    return (
        <Box bgGradient="linear(-45deg, #FF1493, #8A2BE2, #4B0082)" h="100vh">
            <Center h="80vh">
                <Card
                    p={4}
                    boxShadow="lg"
                    minW="30rem"
                    textAlign="center"
                    bg="white"
                >
                    <Box textAlign="left" p="0.5rem">
                        <Logo/>
                        <Heading size="md">Create a new MDM tenant</Heading>
                    </Box>
                    <Divider/>
                    <TenantForm/>
                </Card>
            </Center>
        </Box>
    )
}