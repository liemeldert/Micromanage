"use client";
import { useEffect, useState } from "react";
import { getProviders, signIn, useSession } from "next-auth/react";
import {
    Box,
    Button,
    Card,
    Heading,
    Link,
    Spinner,
    Text,
    VStack,
    Tooltip,
    Center,
    Divider,
    Icon
} from "@chakra-ui/react";
import { FaGithub, FaGoogle  } from "react-icons/fa";
import { LuLogIn } from "react-icons/lu";
import { redirect } from "next/navigation";
import React from "react";
import Logo from "@/app/components/branding";

export default function LoginCard() {
    const [providers, setProviders] = useState<Record<string, any> | null>(null);
    const { data: session, status } = useSession();
    const [loginBox, setLoginBox] = useState<JSX.Element | null>(null);

    useEffect(() => {
        if (status === "loading") {
            setLoginBox(<Spinner size="xl" />);
        } else if (session) {
            redirect("/");
        } else if (providers) {
            setLoginBox(
                <Box minH="3rem" w="100%">
                    <VStack spacing={4}>
                        {Object.keys(providers).map((provider) => {
                            let selected_icon;
                            switch (provider) {
                                case "google":
                                    selected_icon = FaGoogle;
                                    break;
                                case "github":
                                    selected_icon = FaGithub;
                                    break;
                                default:
                                    selected_icon = LuLogIn;
                                    break;
                            }
                            return (
                                <Button
                                    key={provider}
                                    onClick={() => signIn(provider)}
                                    leftIcon={<Icon as={selected_icon} />}
                                    colorScheme="teal"
                                >
                                    Sign in with {provider.charAt(0).toUpperCase() + provider.slice(1)}
                                </Button>
                            );
                        })}
                    </VStack>
                </Box>
            );
        } else {
            setLoginBox(<Spinner size="xl" />);
        }
    }, [providers, session, status]); // Dependencies

    useEffect(() => {
        const fetchProviders = async () => {
            const providers = await getProviders();
            console.log(providers);
            setProviders(providers);
        };

        fetchProviders();
    }, []);

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
                        <Logo />
                    </Box>
                    <Divider />
                    <Heading pt="0.75rem" mb={4}>Log in</Heading>
                    {loginBox}
                    <Tooltip label="Make sure the environment variables for the provider are configured properly on the frontend." fontSize="md">
                        <Link mt={4} href="#" color="teal.500">
                            Something missing?
                        </Link>
                    </Tooltip>
                </Card>
            </Center>
        </Box>
    );
}