import { Badge, HStack, IconButton, Td, Tooltip, Tr, useToast } from "@chakra-ui/react";
import { CheckIcon, DeleteIcon, ViewIcon, DownloadIcon } from "@chakra-ui/icons";
import React from "react";
import axios from 'axios';
import { useRouter, useParams } from 'next/navigation';

export function ProfileRow(props: {
    profile: any,
    activeEnrollmentProfile: any,
    fetchProfiles: () => Promise<void>,
    isEnrollment: boolean
}) {
    const { tenant } = useParams();
    const router = useRouter();
    const toast = useToast();

    const handleView = () => {
        router.push(`/${tenant}/profiles/${props.profile._id}`);
    };

    const handleActivate = async () => {
        try {
            await axios.post(`/${tenant}/api/profiles/${props.profile._id}/activate`);
            props.fetchProfiles();
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
        }
    };

    const handleDelete = async () => {
        if (window.confirm('Are you sure you want to delete this profile?')) {
            try {
                await axios.delete(`/${tenant}/api/profiles/${props.profile._id}`);
                props.fetchProfiles();
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
            }
        }
    };

    const handleDownload = async () => {
        try {
            const response = await axios.get(`/${tenant}/api/profiles/${props.profile._id}/download`, {
                responseType: 'blob'
            });
            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', `${props.profile.name}.mobileconfig`);
            document.body.appendChild(link);
            link.click();
            link.remove();
            toast({
                title: 'Profile Downloaded',
                description: 'The profile has been successfully downloaded.',
                status: 'success',
                duration: 5000,
                isClosable: true,
            });
        } catch (error) {
            console.error('Error downloading profile:', error);
            toast({
                title: 'Error',
                description: 'Failed to download the profile.',
                status: 'error',
                duration: 5000,
                isClosable: true,
            });
        }
    };

    return (
        <Tr>
            <Td>{props.profile.name}</Td>
            {props.isEnrollment ? null : <Td>{props.profile.type}</Td>}
            <Td>{props.profile.description}</Td>
            {props.isEnrollment && (
                <Td>
                    {props.profile._id === props.activeEnrollmentProfile ? (
                        <Badge colorScheme="green">Active</Badge>
                    ) : (
                        <Badge colorScheme="gray">Inactive</Badge>
                    )}
                </Td>
            )}
            <Td>
                <HStack spacing={2}>
                    <Tooltip label="View Details">
                        <IconButton
                            aria-label="View profile details"
                            icon={<ViewIcon />}
                            size="sm"
                            onClick={handleView}
                        />
                    </Tooltip>
                    <Tooltip label="Download Profile">
                        <IconButton
                            aria-label="Download profile"
                            icon={<DownloadIcon />}
                            size="sm"
                            colorScheme="blue"
                            onClick={handleDownload}
                        />
                    </Tooltip>
                    {props.isEnrollment && props.profile._id !== props.activeEnrollmentProfile && (
                        <Tooltip label="Activate Profile">
                            <IconButton
                                aria-label="Activate profile"
                                icon={<CheckIcon />}
                                size="sm"
                                colorScheme="green"
                                onClick={handleActivate}
                            />
                        </Tooltip>
                    )}
                    <Tooltip label="Delete Profile">
                        <IconButton
                            aria-label="Delete profile"
                            icon={<DeleteIcon />}
                            size="sm"
                            colorScheme="red"
                            onClick={handleDelete}
                        />
                    </Tooltip>
                </HStack>
            </Td>
        </Tr>
    );
}