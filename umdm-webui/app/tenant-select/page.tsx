"use client"

import {Box, Button, Card, Center, Divider, Heading, Tooltip} from "@chakra-ui/react";
import Logo from "@/app/components/branding";
import React from "react";
import {signOut, useSession} from "next-auth/react";
import {useRouter} from "next/navigation";
import {ITenant, saveCurrentTenant} from "@/lib/tenant";

export default function TenantSelect() {
    const [allowedTenants, setAllowedTenants] = React.useState([]);
    const [loading, setLoading] = React.useState(true);
    const [error, setError] = React.useState("");

    const {data: session, status} = useSession();
    const router = useRouter();

    const handleTenantClick = (tenant: ITenant) => {
        saveCurrentTenant(tenant);
        router.push(`/${tenant._id}`);
    }


    React.useEffect(() => {
        const fetchTenants = async () => {
            setLoading(true);
            try {
                console.log("User ID: ", session?.user?.id);
                if (!session?.user?.id) {
                    throw new Error('No user ID');
                }

                const response = await fetch(`/api/get_allowed_tenants/`);
                if (!response.ok) {
                    throw new Error('Failed to fetch tenants');
                }
                const data = await response.json();
                console.log(data)
                setAllowedTenants(data);
            } catch (err) {
                if (err instanceof Error) {
                    setError(err.message);
                } else {
                    setError('An unknown error occurred');
                }
            } finally {
                setLoading(false);
            }
        };

        if (status === "authenticated") {
            fetchTenants();
        }
    }, [status, session?.user?.id]);

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
                        <Heading size="md">Select a Tenant</Heading>
                    </Box>
                    <Divider/>
                    {loading ? (
                        <p>Loading...</p>
                    ) : error ? (
                        <>
                            <p>{error}</p>
                            <Button onClick={() => {
                                signOut()
                            }}>Sign out</Button>
                        </>
                    ) : (
                        <Box mt={4}>
                            {allowedTenants.map((tenant: ITenant) => (
                                <Tooltip key={tenant._id} label={tenant.description} aria-label={tenant.description}>
                                    <Button onClick={() => (handleTenantClick(tenant))} color="blue.500"
                                            fontSize="xl">{tenant.name}</Button>
                                </Tooltip>
                            ))}
                        </Box>
                    )}
                    <Button onClick={() => router.push("/tenant-create")} mt={"0.5rem"}>Create a new tenant</Button>
                </Card>
            </Center>
        </Box>
    )
}