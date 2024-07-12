"use client";
import { useEffect, useState } from "react";
import { signOut, useSession } from "next-auth/react";
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
} from "@chakra-ui/react";
import React from "react";
import Logo from "@/app/components/branding";

export default function LoginCard() {
    const { data: session } = useSession();

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
                    <Heading pt="0.75rem" mb={4}>Uh oh!</Heading>
                    <Box w="100%" p="0.75rem">
                        <Heading size="md">This account does not have access to this portal.</Heading>
                        <Text mt={4}>If you believe this is a mistake, please contact your administrator.</Text>
                        <Text>Please make sure you are signed into the correct account.</Text>
                        
                        <Button
                            mt={4}
                            colorScheme="teal"
                            onClick={() => signOut()}
                        >
                            Logout
                        </Button>
                        
                    </Box>
                    <Tooltip label={"user id: " + (session?.user?.id || "unknown") + "\nuser email: " + (session?.user?.email)} fontSize="md">
                        <Link mt={4} href="#" color="teal.500">
                            Useful details for admins
                        </Link>
                    </Tooltip>
                </Card>
            </Center>
        </Box>
    );
}
