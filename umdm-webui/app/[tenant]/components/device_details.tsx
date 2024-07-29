"use client";

import React, { useEffect, useState } from "react";
import { useRouter, useParams } from "next/navigation";
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
  Flex,
  Spacer
} from "@chakra-ui/react";
import { getDeviceDetails, Device, sendCommand } from "@/lib/micromdm";
import commands from "@/lib/commands.json";
import WebhookEvents from "./webhook_events";

const DeviceDetails: React.FC = () => {
  const router = useRouter();
  const { udid } = useParams();
  const [device, setDevice] = useState<Device | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedCommand, setSelectedCommand] = useState<any>(null);
  const [commandParams, setCommandParams] = useState<any>({});

  const { isOpen, onOpen, onClose } = useDisclosure();

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

  const handleSendCommand = async () => {
    try {
      const command = {
        request_type: selectedCommand.name,
        ...commandParams,
      };
      await sendCommand(udid as string, command);
      alert("Command sent successfully");
    } catch (error) {
      alert("Error sending command");
    } finally {
      onClose();
    }
  };

  const handleOpenModal = (command: any) => {
    setSelectedCommand(command);
    setCommandParams({});
    onOpen();
  };

  const pingDevice = async () => {
    try {
      await sendCommand(udid as string, {
        request_type: "DeviceInformation",
        // todo: mode this elsewhere so I don't have to keep searing my eyes on this
        queries: [
          "UDID",
          "Languages",
          "Locales",
          "DeviceID",
          "OrganizationInfo",
          "LastCloudBackupDate",
          "AwaitingConfiguration",
          "MDMOptions",
          "iTunesStoreAccountIsActive",
          "iTunesStoreAccountHash",
          "DeviceName",
          "OSVersion",
          "BuildVersion",
          "ModelName",
          "Model",
          "ProductName",
          "SerialNumber",
          "DeviceCapacity",
          "AvailableDeviceCapacity",
          "BatteryLevel",
          "CellularTechnology",
          "ICCID",
          "BluetoothMAC",
          "WiFiMAC",
          "EthernetMACs",
          "CurrentCarrierNetwork",
          "SubscriberCarrierNetwork",
          "CurrentMCC",
          "CurrentMNC",
          "SubscriberMCC",
          "SubscriberMNC",
          "SIMMCC",
          "SIMMNC",
          "SIMCarrierNetwork",
          "CarrierSettingsVersion",
          "PhoneNumber",
          "DataRoamingEnabled",
          "VoiceRoamingEnabled",
          "PersonalHotspotEnabled",
          "IsRoaming",
          "IMEI",
          "MEID",
          "ModemFirmwareVersion",
          "IsSupervised",
          "IsDeviceLocatorServiceEnabled",
          "IsActivationLockEnabled",
          "IsDoNotDisturbInEffect",
          "EASDeviceIdentifier",
          "IsCloudBackupEnabled",
          "OSUpdateSettings",
          "LocalHostName",
          "HostName",
          "CatalogURL",
          "IsDefaultCatalog",
          "PreviousScanDate",
          "PreviousScanResult",
          "PerformPeriodicCheck",
          "AutomaticCheckEnabled",
          "BackgroundDownloadEnabled",
          "AutomaticAppInstallationEnabled",
          "AutomaticOSInstallationEnabled",
          "AutomaticSecurityUpdatesEnabled",
          "OSUpdateSettings",
          "LocalHostName",
          "HostName",
          "IsMultiUser",
          "IsMDMLostModeEnabled",
          "MaximumResidentUsers",
          "PushToken",
          "DiagnosticSubmissionEnabled",
          "AppAnalyticsEnabled",
          "IsNetworkTethered",
          "ServiceSubscriptions",
        ],
      });
      alert("Ping sent successfully");
    } catch (error) {
      alert("Error sending ping");
    }
  };

  const renderCommandParams = () => {
    if (!selectedCommand || !selectedCommand.parameters) return null;

    return Object.entries(selectedCommand.parameters).map(
      ([key, param]: [string, any]) => (
        <FormControl key={key} mt={4}>
          <FormLabel>{param.description}</FormLabel>
          {param.type === "array" ? (
            <Input
              placeholder={`Enter ${key}`}
              onChange={(e) =>
                setCommandParams({
                  ...commandParams,
                  [key]: e.target.value.split(","),
                })
              }
            />
          ) : (
            <Input
              placeholder={`Enter ${key}`}
              onChange={(e) =>
                setCommandParams({ ...commandParams, [key]: e.target.value })
              }
            />
          )}
        </FormControl>
      )
    );
  };

  const renderCommandsBySection = () => {
    const sections = commands.reduce((acc: any, command: any) => {
      if (!acc[command.section]) {
        acc[command.section] = [];
      }
      acc[command.section].push(command);
      return acc;
    }, {});

    return Object.entries(sections).map(
      ([section, commands]: [string, any]) => (
        <Box key={section} mt={"0.25rem"}>
          <Heading size="sm">{section}</Heading>
          {commands.map((command: any) => (
            <Button
              key={command.name}
              colorScheme="blue"
              onClick={() => handleOpenModal(command)}
              leftIcon={<Icon as={command.icon} />}
              mr={3}
              mb={3}
            >
              {command.friendlyName}
            </Button>
          ))}
        </Box>
      )
    );
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
    <Box w="100%">
      <Heading>{device.DeviceName}</Heading>
      <Box mt={5}>
        <Button
          onClick={() => {
            pingDevice();
          }}
        >
          Ping device for new information
        </Button>
        <Text>UDID: {device.UDID}</Text>
        <Text>Serial Number: {device.SerialNumber}</Text>
        <Text>Model: {device.Model}</Text>
        <Text>OS Version: {device.OSVersion}</Text>
      </Box>
    
      <Heading size="md" mt={5}>
        Advanced Device Commmands
      </Heading>
      <Box mt={"0.25rem"}>{renderCommandsBySection()}</Box>

      <Flex w="100%">
          <Box>
              <Heading size="md" mt={5}>
                Device Details
              </Heading>
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
                      <Td>
                        {Array.isArray(value) ? value.join(", ") : value?.toString()}
                      </Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
          </Box>
          <Spacer />
          <Box flex="1">
            <WebhookEvents udid={device.UDID} />
          </Box>
      </Flex>

      <Modal isOpen={isOpen} onClose={onClose}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>Send {selectedCommand?.friendlyName}</ModalHeader>
          <ModalCloseButton />
          <ModalBody>{renderCommandParams()}</ModalBody>
          <ModalFooter>
            <Button colorScheme="blue" mr={3} onClick={handleSendCommand}>
              Send
            </Button>
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Box>
  );
};

export default DeviceDetails;
