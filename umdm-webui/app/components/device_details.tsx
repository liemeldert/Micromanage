// src/components/DeviceDetails.tsx
'use client';

import React, { useEffect, useState } from 'react';
import { useRouter, useParams } from 'next/navigation';
import {
  Box,
  Spinner,
  Table,
  Tbody,
  Td,
  Th,
  Thead,
  Tr,
  Text,
  Button,
  Heading,
  Center,
  Icon,
  useDisclosure,
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
} from '@chakra-ui/react';
import { getDeviceDetails, Device, sendCommand } from '@/lib/micromdm';
import { FaLock, FaUnlock, FaTrashAlt, FaRecycle } from 'react-icons/fa';

const DeviceDetails: React.FC = () => {
  const router = useRouter();
  const { udid } = useParams();
  const [device, setDevice] = useState<Device | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  const { isOpen, onOpen, onClose } = useDisclosure();
  const [commandType, setCommandType] = useState<string | null>(null);

  useEffect(() => {
    if (udid) {
      const fetchDeviceDetails = async () => {
        const deviceData = await getDeviceDetails(udid as string);
        setDevice(deviceData);
        setLoading(false);
      };

      fetchDeviceDetails();
    }
  }, [udid]);

  const handleSendCommand = async (command: any) => {
    try {
      await sendCommand(udid as string, command);
      alert('Command sent successfully');
    } catch (error) {
      alert('Error sending command');
    }
  };

  const handleCommand = (type: string) => {
    setCommandType(type);
    onOpen();
  };

  const executeCommand = () => {
    if (commandType) {
      const command = { request_type: commandType };
      handleSendCommand(command);
      onClose();
    }
  };

  if (loading) {
    return (
      <Center h="80%">
        <Spinner size="xl" />
      </Center>
    );
  }

  if (!device) {
    return <Text>Device not found.</Text>;
  }

  return (
    <Box>
      <Heading>{device.DeviceName}</Heading>
      <Box mt={5}>
        <Heading size="md">Device Commands</Heading>
        <Button
          colorScheme="blue"
          onClick={() => handleCommand('DeviceLock')}
          leftIcon={<Icon as={FaLock} />}
          mr={3}
        >
          Lock Device
        </Button>
        <Button
          colorScheme="blue"
          onClick={() => handleCommand('ClearPasscode')}
          leftIcon={<Icon as={FaUnlock} />}
          mr={3}
        >
          Clear Passcode
        </Button>
        <Button
          colorScheme="red"
          onClick={() => handleCommand('EraseDevice')}
          leftIcon={<Icon as={FaTrashAlt} />}
          mr={3}
        >
          Erase Device
        </Button>
        <Button
          colorScheme="blue"
          onClick={() => handleCommand('RestartDevice')}
          leftIcon={<Icon as={FaRecycle} />}
        >
          Restart Device
        </Button>
      </Box>

      <Heading size="md" mt={5}>Device Details</Heading>
      <Table variant="simple">
        <Thead>
          <Tr>
            <Th>Field</Th>
            <Th>Value</Th>
          </Tr>
        </Thead>
        <Tbody>
          {Object.entries(device).map(([key, value]) => (
            <Tr key={key}>
              <Td>{key}</Td>
              <Td>{Array.isArray(value) ? value.join(', ') : value?.toString()}</Td>
            </Tr>
          ))}
        </Tbody>
      </Table>

      <Modal isOpen={isOpen} onClose={onClose}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>Send Command</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <FormControl>
              <FormLabel>Command Type</FormLabel>
              <Input value={commandType} readOnly />
            </FormControl>
          </ModalBody>
          <ModalFooter>
            <Button colorScheme="blue" mr={3} onClick={executeCommand}>
              Send
            </Button>
            <Button variant="ghost" onClick={onClose}>Cancel</Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Box>
  );
};

export default DeviceDetails;
