import React, { useState } from "react";
import {
    Button,
    FormControl,
    FormLabel,
    Input,
    Modal,
    ModalBody,
    ModalCloseButton,
    ModalContent,
    ModalFooter,
    ModalHeader,
    ModalOverlay,
    Select,
    Textarea,
    VStack,
    useToast
} from "@chakra-ui/react";
import axios from 'axios';
import { useParams } from 'next/navigation';

export const profileTypes = ['Configuration', 'Restriction', 'App'];

export function AddProfileModal(props: {
    open: boolean,
    onClose: () => void,
    fetchProfiles: () => Promise<void>
}) {
    const { tenant } = useParams();
    const toast = useToast();
    const [newProfile, setNewProfile] = useState({ name: '', description: '', type: '', profileData: '' });
    const [isLoading, setIsLoading] = useState(false);

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
            props.fetchProfiles();
            props.onClose();
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

    return (
        <Modal isOpen={props.open} onClose={props.onClose}>
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
                                {profileTypes.map(type => (
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
                    <Button variant="ghost" onClick={props.onClose}>Cancel</Button>
                </ModalFooter>
            </ModalContent>
        </Modal>
    );
}