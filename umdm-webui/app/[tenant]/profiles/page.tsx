'use client';

import React, { useState, useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import {
    Box,
    Button,
    Heading,
    Table,
    Thead,
    Tbody,
    Tr,
    Th,
    Td,
    Modal,
    ModalOverlay,
    ModalContent,
    ModalHeader,
    ModalFooter,
    ModalBody,
    ModalCloseButton,
    FormControl,
    FormLabel,
    Input,
    Textarea,
    Select,
    useDisclosure,
    useToast,
    VStack,
    HStack,
    Text,
    IconButton,
    Tooltip,
    Badge,
} from '@chakra-ui/react';
import { AddIcon, DeleteIcon, ViewIcon, CheckIcon } from '@chakra-ui/icons';
import axios from 'axios';

const profileTypes = ['Configuration', 'Restriction', 'App'];

export default function ProfilesPage() {
    const { tenant } = useParams();
    const router = useRouter();
    const [profiles, setProfiles] = useState([]);
    const [enrollmentProfiles, setEnrollmentProfiles] = useState([]);
    const [activeEnrollmentProfile, setActiveEnrollmentProfile] = useState(null);
    const { isOpen, onOpen, onClose } = useDisclosure();
    const [newProfile, setNewProfile] = useState({ name: '', description: '', type: '', profileData: '' });
    const toast = useToast();
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
            const active = allProfiles.find((profile: { type: string; isActive: any; }) => profile.type === 'Enrollment' && profile.isActive);
            setActiveEnrollmentProfile(active ? active._id : null);
        } catch (error) {
            console.error('Error fetching profiles:', error);
            toast({
                title: 'Error',
                description: 'Failed to fetch profiles.',
                status: 'error',
                duration: 5000,
                isClosable: true,
            });
        } finally {
            setIsLoading(false);
        }
    };

    const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
        const { name, value } = e.target;
        setNewProfile({ ...newProfile, [name]: value });
    };

    const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = (event) => {
                const base64 = event.target?.result as string;
                setNewProfile({ ...newProfile, profileData: base64.split(',')[1] });
            };
            reader.readAsDataURL(file);
        }
    };

    const handleSubmit = async () => {
        setIsLoading(true);
        try {
            await axios.post(`/${tenant}/api/profiles`, newProfile);
            fetchProfiles();
            onClose();
            toast({
                title: 'Profile created.',
                description: 'The new profile has been successfully created.',
                status: 'success',
                duration: 5000,
                isClosable: true,
            });
        } catch (error) {
            console.error('Error creating profile:', error);
            toast({
                title: 'Error',
                description: 'Failed to create the profile.',
                status: 'error',
                duration: 5000,
                isClosable: true,
            });
        } finally {
            setIsLoading(false);
        }
    };

    const handleDelete = async (profileId: string) => {
        if (window.confirm('Are you sure you want to delete this profile?')) {
            setIsLoading(true);
            try {
                await axios.delete(`/${tenant}/api/profiles/${profileId}`);
                fetchProfiles();
                toast({
                    title: 'Profile deleted.',
                    description: 'The profile has been successfully deleted.',
                    status: 'success',
                    duration: 5000,
                    isClosable: true,
                });
            } catch (error) {
                console.error('Error deleting profile:', error);
                toast({
                    title: 'Error',
                    description: 'Failed to delete the profile.',
                    status: 'error',
                    duration: 5000,
                    isClosable: true,
                });
            } finally {
                setIsLoading(false);
            }
        }
    };

    const handleActivateEnrollmentProfile = async (profileId: string) => {
        setIsLoading(true);
        try {
            await axios.post(`/${tenant}/api/profiles/${profileId}/activate`);
            fetchProfiles();
            toast({
                title: 'Enrollment Profile Activated',
                description: 'The enrollment profile has been successfully activated.',
                status: 'success',
                duration: 5000,
                isClosable: true,
            });
        } catch (error) {
            console.error('Error activating enrollment profile:', error);
            toast({
                title: 'Error',
                description: 'Failed to activate the enrollment profile.',
                status: 'error',
                duration: 5000,
                isClosable: true,
            });
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
                                        <Tr key={profile._id}>
                                            <Td>{profile.name}</Td>
                                            <Td>{profile.description}</Td>
                                            <Td>
                                                {profile._id === activeEnrollmentProfile ? (
                                                    <Badge colorScheme="green">Active</Badge>
                                                ) : (
                                                    <Badge colorScheme="gray">Inactive</Badge>
                                                )}
                                            </Td>
                                            <Td>
                                                <HStack spacing={2}>
                                                    <Tooltip label="View Details">
                                                        <IconButton
                                                            aria-label="View profile details"
                                                            icon={<ViewIcon />}
                                                            size="sm"
                                                            onClick={() => router.push(`/${tenant}/profiles/${profile._id}`)}
                                                        />
                                                    </Tooltip>
                                                    {profile._id !== activeEnrollmentProfile && (
                                                        <Tooltip label="Activate Profile">
                                                            <IconButton
                                                                aria-label="Activate profile"
                                                                icon={<CheckIcon />}
                                                                size="sm"
                                                                colorScheme="green"
                                                                onClick={() => handleActivateEnrollmentProfile(profile._id)}
                                                            />
                                                        </Tooltip>
                                                    )}
                                                    <Tooltip label="Delete Profile">
                                                        <IconButton
                                                            aria-label="Delete profile"
                                                            icon={<DeleteIcon />}
                                                            size="sm"
                                                            colorScheme="red"
                                                            onClick={() => handleDelete(profile._id)}
                                                        />
                                                    </Tooltip>
                                                </HStack>
                                            </Td>
                                        </Tr>
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
                                        <Tr key={profile._id}>
                                            <Td>{profile.name}</Td>
                                            <Td>{profile.type}</Td>
                                            <Td>{profile.description}</Td>
                                            <Td>
                                                <HStack spacing={2}>
                                                    <Tooltip label="View Details">
                                                        <IconButton
                                                            aria-label="View profile details"
                                                            icon={<ViewIcon />}
                                                            size="sm"
                                                            onClick={() => router.push(`/${tenant}/profiles/${profile._id}`)}
                                                        />
                                                    </Tooltip>
                                                    <Tooltip label="Delete Profile">
                                                        <IconButton
                                                            aria-label="Delete profile"
                                                            icon={<DeleteIcon />}
                                                            size="sm"
                                                            colorScheme="red"
                                                            onClick={() => handleDelete(profile._id)}
                                                        />
                                                    </Tooltip>
                                                </HStack>
                                            </Td>
                                        </Tr>
                                    ))}
                                </Tbody>
                            </Table>
                        </Box>
                    </>
                )}
            </VStack>

            <Modal isOpen={isOpen} onClose={onClose}>
                <ModalOverlay />
                <ModalContent>
                    <ModalHeader>Create New Profile</ModalHeader>
                    <ModalCloseButton />
                    <ModalBody>
                        <VStack spacing={4}>
                            <FormControl isRequired>
                                <FormLabel>Name</FormLabel>
                                <Input name="name" value={newProfile.name} onChange={handleInputChange} />
                            </FormControl>
                            <FormControl isRequired>
                                <FormLabel>Type</FormLabel>
                                <Select name="type" value={newProfile.type} onChange={handleInputChange}>
                                    <option value="">Select a type</option>
                                    <option value="Enrollment">Enrollment</option>
                                    {profileTypes.map((type) => (
                                        <option key={type} value={type}>
                                            {type}
                                        </option>
                                    ))}
                                </Select>
                            </FormControl>
                            <FormControl>
                                <FormLabel>Description</FormLabel>
                                <Textarea name="description" value={newProfile.description} onChange={handleInputChange} />
                            </FormControl>
                            <FormControl isRequired>
                                <FormLabel>Profile File</FormLabel>
                                <Input type="file" onChange={handleFileUpload} accept=".mobileconfig" />
                            </FormControl>
                        </VStack>
                    </ModalBody>
                    <ModalFooter>
                        <Button colorScheme="blue" mr={3} onClick={handleSubmit} isLoading={isLoading}>
                            Create
                        </Button>
                        <Button variant="ghost" onClick={onClose}>Cancel</Button>
                    </ModalFooter>
                </ModalContent>
            </Modal>
        </Box>
    );
}