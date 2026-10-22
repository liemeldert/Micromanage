"use client";

import {useEffect} from "react";
import {useRouter} from "next/navigation";
import {useAuth} from "../../lib/auth-context";
import {Center, Loader} from "@mantine/core";

export default function Root() {
    const {isAuthenticated, hydrated} = useAuth();
    const router = useRouter();

    useEffect(() => {
        if (!hydrated) return;
        router.replace(isAuthenticated ? "/dashboard" : "/login");
    }, [isAuthenticated, hydrated, router]);

    return (
        <Center h="100vh">
            <Loader/>
        </Center>
    );
}
