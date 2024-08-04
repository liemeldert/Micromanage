'use client';
import {Box, Heading} from "@chakra-ui/react";
import React from "react";
import {useRouter} from "next/navigation";


export default function Home() {
    const router = useRouter();
    React.useEffect(() => {
        router.push("/auth/login");
    });

    return (
        <Box>
            <Heading>Welcome to uMDM, redirecting to login.</Heading>
        </Box>
    );
}
