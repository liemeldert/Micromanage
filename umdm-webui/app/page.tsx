'use client';
import {Heading} from "@chakra-ui/react";
import React from "react";
import {useRouter} from "next/navigation";
import {CenterCardLogo} from "@/app/components/CenterCard";


export default function Home() {
    const router = useRouter();
    React.useEffect(() => {
        router.push("/auth/login");
    });

    return (
        <CenterCardLogo>
            <Heading m={"4"} size={"md"}>Welcome to Micromanage, redirecting to login.</Heading>
        </CenterCardLogo>
    );
}
