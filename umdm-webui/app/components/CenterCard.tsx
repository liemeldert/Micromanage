import {Box, Card, Center, Divider} from "@chakra-ui/react";
import Logo from "@/app/components/branding";
import React from "react";

export default function CenterCard({
                                       children
                                   }: Readonly<{
    children: React.ReactNode;
}>) {
    return (
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
                </Box>
                <Divider/>
                {children}
            </Card>
        </Center>
    )
}

export function CenterCardLogo({
                                   children
                               }: Readonly<{
    children: React.ReactNode;
}>) {
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
                    </Box>
                    <Divider/>
                    {children}
                </Card>
            </Center>
        </Box>
    )
}
