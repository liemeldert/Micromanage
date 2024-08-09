'use client';

import React, { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import {
    Box,
    Button,
    Heading,
    HStack,
    Table,
    Tbody,
    Text,
    Th,
    Thead,
    Tr,
    useDisclosure,
    VStack,
} from '@chakra-ui/react';
import { AddIcon } from '@chakra-ui/icons';
import axios from 'axios';
import { ProfileRow } from "@/app/[tenant]/profiles/profileRow";
import { AddProfileModal } from "@/app/[tenant]/profiles/addProfileModal";

export default function ProfilesPage() {
    const { tenant } = useParams();
    const [profiles, setProfiles] = useState([]);
    const [enrollmentProfiles, setEnrollmentProfiles] = useState([]);
    const [activeEnrollmentProfile, setActiveEnrollmentProfile] = useState(null);
    const { isOpen, onOpen, onClose } = useDisclosure();
    const [isLoading, setIsLoading] = useState(false);

    useEffect(() => {
        fetchProfiles();
    }, []);

    const fetchProfiles = async () => {
        setIsLoading(true);
        try {
            const response = await axios.get(`/${tenant}/api/profiles`);
            const allProfiles = response.data;
            setProfiles(allProfiles.filter((profile: { type: string; }) => profile.type !== 'Enrollment'));
            setEnrollmentProfiles(allProfiles.filter((profile: { type: string; }) => profile.type === 'Enrollment'));
            const active = allProfiles.find((profile: {
                type: string;
                isActive: any;
            }) => profile.type === 'Enrollment' && profile.isActive);
            setActiveEnrollmentProfile(active ? active._id : null);
        } catch (error) {
            console.error('Error fetching profiles:', error);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <Box>
            <VStack align="stretch" spacing={8}>
                <HStack justify="space-between">
                    <Heading>Profiles</Heading>
                    <Button leftIcon={<AddIcon />} colorScheme="blue" onClick={onOpen}>
                        Add New Profile
                    </Button>
                </HStack>

                {isLoading ? (
                    <Text>Loading...</Text>
                ) : (
                    <>
                        <Box>
                            <Heading size="md" mb={4}>Enrollment Profiles</Heading>
                            <Table variant="simple">
                                <Thead>
                                    <Tr>
                                        <Th>Name</Th>
                                        <Th>Description</Th>
                                        <Th>Status</Th>
                                        <Th>Actions</Th>
                                    </Tr>
                                </Thead>
                                <Tbody>
                                    {enrollmentProfiles.map((profile: any) => (
                                        <ProfileRow
                                            key={profile._id}
                                            profile={profile}
                                            activeEnrollmentProfile={activeEnrollmentProfile}
                                            fetchProfiles={fetchProfiles}
                                            isEnrollment={true}
                                        />
                                    ))}
                                </Tbody>
                            </Table>
                        </Box>

                        <Box>
                            <Heading size="md" mb={4}>Other Profiles</Heading>
                            <Table variant="simple">
                                <Thead>
                                    <Tr>
                                        <Th>Name</Th>
                                        <Th>Type</Th>
                                        <Th>Description</Th>
                                        <Th>Actions</Th>
                                    </Tr>
                                </Thead>
                                <Tbody>
                                    {profiles.map((profile: any) => (
                                        <ProfileRow
                                            key={profile._id}
                                            profile={profile}
                                            activeEnrollmentProfile={activeEnrollmentProfile}
                                            fetchProfiles={fetchProfiles}
                                            isEnrollment={false}
                                        />
                                    ))}
                                </Tbody>
                            </Table>
                        </Box>
                    </>
                )}
            </VStack>

            <AddProfileModal
                open={isOpen}
                onClose={onClose}
                fetchProfiles={fetchProfiles}
            />
        </Box>
    );
}