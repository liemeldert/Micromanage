'use client';

import React from 'react';
import {Box, Divider, Heading, Text} from '@chakra-ui/react';
import DeviceList from '@/app/[tenant]/devices/device_list';

const Page: React.FC = () => {

    return (
        <Box>
            <Heading as="h1" size="lg" mb={4}>Devices</Heading>
            <Text mb="1rem">Click on a device to view more details. Ignore last two rows if DEP is not in use.</Text>
            <Text>MDM Devices is a list of devices that got a profile and pinged the MDM server at some point.</Text>
            <Text>Checked-in Devices pinged our server providing specific device information</Text>
            <Divider mb="1rem"/>
            <DeviceList/>
        </Box>
    );
};

export default Page;
