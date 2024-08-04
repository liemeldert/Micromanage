import React, {useState} from 'react';
import {Box, Button, FormControl, FormLabel, Input, Text, useToast} from '@chakra-ui/react';
import {useRouter} from "next/navigation";

const TenantForm = () => {
    const [name, setName] = useState('');
    const [description, setDescription] = useState('');
    const [mdm_secret, setMdm_secret] = useState('');
    const [mdm_url, setMdm_url] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const toast = useToast();
    const router = useRouter();

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        try {
            const response = await fetch('/api/create_tenant', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({name, description, mdm_secret, mdm_url}),
            });

            if (!response.ok) {
                throw new Error('Failed to create tenant');
            }

            const data = await response.json();
            toast({
                title: 'Tenant created.',
                description: `Tenant ${data.name} was created successfully.`,
                status: 'success',
                duration: 5000,
                isClosable: true,
            });

            setName('');
            setDescription('');
            setMdm_secret('');
            setMdm_url('');

            router.push("/tenant-select");
        } catch (err) {
            if (err instanceof Error) {
                setError(err.message);
            } else {
                setError('An unknown error occurred');
            }
        } finally {
            setLoading(false);
        }
    };

    return (
        <Box maxW="md" mx="auto" mt={8} p={4}>
            <form onSubmit={handleSubmit}>
                <FormControl id="name" isRequired>
                    <FormLabel>Organization Name</FormLabel>
                    <Input
                        type="text"
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                    />
                </FormControl>
                <FormControl id="description" mt={4}>
                    <FormLabel>Tenant Description</FormLabel>
                    <Input
                        type="text"
                        value={description}
                        onChange={(e) => setDescription(e.target.value)}
                    />
                </FormControl>
                <Text mt={4}>Don't have a MicroMDM server? Please contact us to host one for you, or host one
                    yourself.</Text>
                <FormControl id="mdmurl" mt={4}>
                    <FormLabel>MicroMDM Server URL</FormLabel>
                    <Input
                        type="text"
                        value={mdm_url}
                        onChange={(e) => setMdm_url(e.target.value)}
                    />
                </FormControl>
                <FormControl id="mdmtoken" mt={4}>
                    <FormLabel>MicroMDM Server Token</FormLabel>
                    <Input
                        type="password"
                        value={mdm_secret}
                        onChange={(e) => setMdm_secret(e.target.value)}
                    />
                </FormControl>
                {error && <Text color="red.500" mt={2}>{error}</Text>}
                <Text mt={4}>We'll help you add more users later.</Text>
                <Button
                    mt={4}
                    colorScheme="teal"
                    isLoading={loading}
                    type="submit"
                >
                    Create Tenant
                </Button>
            </form>
        </Box>
    );
};

export default TenantForm;