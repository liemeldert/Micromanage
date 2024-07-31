"use client"

import {Box, Card, Center, Divider, Heading, Link, Tooltip} from "@chakra-ui/react";
import Logo from "@/app/components/branding";
import React from "react";
import {useSession} from "next-auth/react";

export default function TenantSelect() {
    const [allowedTenants, setAllowedTenants] = React.useState([]);
    const [loading, setLoading] = React.useState(true);
    const [error, setError] = React.useState("");
    const { data: session, status } = useSession();

    React.useEffect(() => {
        const fetchTenants = async () => {
            setLoading(true);
            try {
                console.log("User ID: ", session?.user?.id);
                const response = await fetch(`/api/get-allowed-tenants/${session?.user?.id}`);
                if (!response.ok) {
                    throw new Error('Failed to fetch tenants');
                }
                const data = await response.json();
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
                    <Logo/>
                    <Heading as="h1" size="2xl" mb={4}>Select a Tenant</Heading>
                    <Divider/>
                    {loading ? (
                        <p>Loading...</p>
                    ) : error ? (
                        <p>{error}</p>
                    ) : (
                        <Box mt={4}>
                            {allowedTenants.map((tenant) => (
                                <Tooltip key={tenant._id} label={tenant.description} aria-label={tenant.description}>
                                    <Link href={`/tenant/${tenant._id}`} color="blue.500"
                                          fontSize="xl">{tenant.name}</Link>
                                </Tooltip>
                            ))}
                        </Box>
                    )}
                </Card>
            </Center>
        </Box>
    )
}