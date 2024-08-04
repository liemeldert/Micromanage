'use client';

import React, {useEffect, useState} from 'react';
import {Box, Button, Flex, Icon, Spacer, Text} from '@chakra-ui/react';
import {IconType} from 'react-icons';
import {useRouter} from 'next/navigation';
import sidebarConfig from '@/app/components/sidebar.json';
import {signOut, useSession} from 'next-auth/react';
import Logo from './branding';
import {useTenant} from "@/lib/useTenant";

interface SidebarItem {
    label: string;
    icon: string;
    path: string;
}

const Layout: React.FC<{ children: React.ReactNode }> = ({children}) => {
    const [sidebarItems, setSidebarItems] = useState<SidebarItem[]>([]);
    const {data: session, status} = useSession();
    const router = useRouter()

    const tenant = useTenant();

    useEffect(() => {
        setSidebarItems(sidebarConfig);
    }, []);

    const handleNavigation = (path: string) => {
        if (tenant?.tenant?._id) {
            router.push(`/${tenant.tenant._id}${path}`);
        }
    };
    const getIcon = (iconName: string): IconType | null => {
        const icons = require('react-icons/md');
        return icons[iconName] || null;
    };

    return (
        <Flex height="100vh" width="100" overflow="hidden">
            <Box
                as="nav"
                width="250px"
                p={5}
                bg="gray.800"
                color="white"
                position="fixed"
                height="100%"
                overflowY="auto"
            >
                <Logo/>
                {sidebarItems.map((item) => {
                    const IconComponent = getIcon(item.icon);
                    return (
                        <Flex
                            key={item.label}
                            align="center"
                            p={3}
                            mb={2}
                            cursor="pointer"
                            _hover={{bg: 'gray.700'}}
                            onClick={() => handleNavigation(item.path)}
                        >
                            {IconComponent && <Icon as={IconComponent} mr={3}/>}
                            <Text>{item.label}</Text>
                        </Flex>
                    );
                })}
            </Box>
            <Box flex="1" ml="250px">
                <Box
                    as="header"
                    width="100%"
                    p={5}
                    bg="gray.100"
                    borderBottom="1px solid"
                    borderColor="gray.200"
                    position="fixed"
                    zIndex="1000"
                >
                    <Flex justify="space-between" align="center" pr="250px">
                        {/* <Icon as={MdMenu} w={6} h={6} /> */}
                        {/* <Text>Header</Text> */}
                        <Spacer/>
                        <Flex align="center" gap="2">
                            <Text>Welcome, {session?.user?.name || "Loading..."}</Text>
                            <Button onClick={() => signOut()}>Sign out</Button>
                        </Flex>
                    </Flex>
                </Box>
                <Box as="main" p={5} mt="74px" overflowY="auto" height="calc(100vh - 64px)">
                    {children}
                </Box>
            </Box>
        </Flex>
    );
};

export default Layout;
