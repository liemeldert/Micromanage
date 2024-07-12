'use client';
import Image from "next/image";
import styles from "./page.module.css";
import { Box, Heading } from "@chakra-ui/react";
import React from "react";


export default function Home() {
  const apiKey = localStorage.getItem('api_key');

  return (
    <Box>
      <Heading>Welcome to uMDM</Heading>
      {apiKey ? <p>API Key is set</p> : <p>API Key is not set</p>}
    </Box>
  );
}
