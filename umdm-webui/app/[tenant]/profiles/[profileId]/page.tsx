'use client';

import React, {useEffect, useState} from 'react';
import {useParams} from 'next/navigation';
import {Box, Heading, Table, Tbody, Td, Text, Th, Thead, Tr,} from '@chakra-ui/react';
import axios from 'axios';

export default function ProfileDetailsPage() {
    const {tenant, profileId} = useParams();
    const [profile, setProfile] = useState<any>(null);
    const [devices, setDevices] = useState([]);

    useEffect(() => {
        fetchProfileDetails();
        fetchDevicesWithProfile();
    });

    const fetchProfileDetails = async () => {
        try {
            const response = await axios.get(`/${tenant}/api/profiles/${profileId}`);
            setProfile(response.data);
        } catch (error) {
            console.error('Error fetching profile details:', error);
        }
    };

    const fetchDevicesWithProfile = async () => {
        try {
            const response = await axios.get(`/${tenant}/api/devices/with_profile/${profileId}`);
            setDevices(response.data);
        } catch (error) {
            console.error('Error fetching devices with profile:', error);
        }
    };

    if (!profile) {
        return <Box>Loading...</Box>;
    }

    return (
        <Box>
            <Heading mb={4}>{profile.name}</Heading>
            <Text>Type: {profile.type}</Text>
            <Text>Description: {profile.description}</Text>

            <Heading size="md" mt={6} mb={4}>Devices with this profile</Heading>
            <Table variant="simple">
                <Thead>
                    <Tr>
                        <Th>Device Name</Th>
                        <Th>UDID</Th>
                        <Th>Serial Number</Th>
                    </Tr>
                </Thead>
                <Tbody>
                    {devices.map((device: any) => (
                        <Tr key={device.UDID}>
                            <Td>{device.DeviceName}</Td>
                            <Td>{device.UDID}</Td>
                            <Td>{device.SerialNumber}</Td>
                        </Tr>
                    ))}
                </Tbody>
            </Table>
        </Box>
    );
}