import Image from "next/image";
import * as React from "react";
import { Box, Heading } from "@chakra-ui/react";

export default function Logo() {
    return (
        <Heading as="h1" size="lg" fontWeight="bold"
        bgGradient='linear(to-l, #7928CA, #FF0080)'
        bgClip='text'>
            MicroManage
        </Heading>
    );
}