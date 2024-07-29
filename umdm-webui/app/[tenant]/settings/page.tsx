'use client';
import { useState } from 'react';
import { Box, Button, FormControl, FormLabel, Input, Text } from '@chakra-ui/react';
import React from 'react';

const Settings = () => {
    const [apiKey, setApiKey] = useState('');

    const handleApiKeyChange = (event: React.ChangeEvent<HTMLInputElement>) => {
        setApiKey(event.target.value);
    };

    const handleSave = () => {
        localStorage.setItem('api_key', apiKey);
    };

    return (
        <Box>
            <Text>There are no settings yet</Text>
            <FormControl>
                {/* <FormLabel>API Key</FormLabel>
                <Input type="text" value={apiKey} onChange={handleApiKeyChange} /> */}
            </FormControl>
            <Button mt={4} colorScheme="teal" onClick={handleSave}>
                Save
            </Button>
        </Box>
    );
};

export default Settings;