"use client";

import React, {useEffect, useState} from "react";
import {useParams} from "next/navigation";
import {
    Box,
    Button,
    Card,
    Center, Divider,
    Flex,
    FormControl,
    FormLabel,
    Heading,
    Icon,
    Input,
    Image,
    Modal,
    ModalBody,
    ModalCloseButton,
    ModalContent,
    ModalFooter,
    ModalHeader,
    ModalOverlay, SimpleGrid,
    Spacer,
    Spinner,
    Table,
    Tbody,
    Td,
    Text,
    Th,
    Thead,
    Tr,
    useDisclosure,
    useToast, HStack, VStack, TableContainer,
} from "@chakra-ui/react";
import {Device, device_queries, getDeviceDetails, sendCommand} from "@/lib/micromdm";
import commands from "@/lib/commands.json";
import WebhookEvents from "./webhook_events";

const DeviceDetails: React.FC = () => {
    const toast = useToast();
    const {tenant, udid} = useParams() as { tenant: string; udid: string };
    const [device, setDevice] = useState<Device | null>(null);
    const [loading, setLoading] = useState<boolean>(true);
    const [selectedCommand, setSelectedCommand] = useState<any>(null);
    const [commandParams, setCommandParams] = useState<any>({});

    const {isOpen, onOpen, onClose} = useDisclosure();

    useEffect(() => {
        if (udid) {
            const fetchDeviceDetails = async () => {
                const deviceData = await getDeviceDetails(tenant, udid as string);
                setDevice(deviceData);
                setLoading(false);
            };

            fetchDeviceDetails();
        }
    }, [udid, tenant]);

    const handleSendCommand = async () => {
        try {
            const command = {
                request_type: selectedCommand.name,
                ...commandParams,
            };
            await sendCommand(tenant, udid as string, command);
            toast({
                title: "Command sent successfully",
                status: "success",
                duration: 5000,
                isClosable: true,
            });
        } catch (error) {
            toast({
                title: "Error sending command",
                status: "error",
                duration: 5000,
                isClosable: true,
            });
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
            await sendCommand(tenant, udid as string, {
                request_type: "DeviceInformation",
                // todo: mode this elsewhere so I don't have to keep searing my eyes on this
                queries: device_queries,
            });
            toast({
                title: "Ping sent successfully",
                status: "success",
                duration: 5000,
                isClosable: true,
            });
        } catch (error) {
            toast({
                title: "Error sending ping",
                status: "error",
                duration: 5000,
                isClosable: true,
            });
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
                                setCommandParams({...commandParams, [key]: e.target.value})
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
                            leftIcon={<Icon as={command.icon}/>}
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
                <Spinner size="xl"/>
            </Center>
        );
    }

    if (!device) {
        return (
            <Center>
                <Card w={"50%"} p={5}>
                    <Heading>This device has yet to respond to our requests for more information</Heading>
                    <Text>Not what you&apos;re expecting to see?</Text>
                    <Text>Check your profiles and network connections on each device.</Text>
                    <Button
                        onClick={() => {
                            pingDevice();
                        }}
                    >
                        Try to ask device for information again
                    </Button>
                </Card>
            </Center>
        );
    }

    return (
        <Box maxW="100%">
            <Heading>{device.DeviceName}</Heading>
            <HStack spacing={10} alignItems={"stretch"} overflowX={"scroll"} whiteSpace={"nowrap"} p={4} maxW={"90%"}>
                <Card p={4} mt={5} flex={"1 0 0"} minW={"450px"}>
                    <Center>
                        <VStack>
                            <Image src={`https://img.appledb.dev/device@256/${device.Model}/0.avif`} maxH={"256px"} maxW={"256px"} />
                            <Box>
                                <HStack>
                                    <Button
                                        onClick={() => {
                                            pingDevice();
                                        }}
                                        w={"50%"}
                                    >
                                        Refresh
                                    </Button>
                                    <Button
                                        onClick={() => {
                                            pingDevice();
                                        }}
                                        w={"50%"}
                                    >
                                        Placeholder
                                    </Button>
                                </HStack>
                                <Text>UDID: {device.UDID}</Text>
                                <Text>Serial Number: {device.SerialNumber}</Text>
                                <Text>Model: {device.Model}</Text>
                                <Text>OS Version: {device.OSVersion}</Text>
                            </Box>
                        </VStack>
                    </Center>
                </Card>

                <Card p={4} mt={5} flex={"1 0 0"} minW={"450px"}>
                    <Heading>Placeholder</Heading>
                </Card>

                <Card p={4} mt={5} flex={"1 0 0"} minW={"450px"}>
                    <Heading>Placeholder</Heading>
                </Card>

                <Card p={4} mt={5} flex={"1 0 0"} minW={"450px"}>
                    <Heading>Placeholder</Heading>
                </Card>

                <Card p={4} mt={5} flex={"1 0 0"} minW={"450px"}>
                    <Heading>Placeholder</Heading>
                </Card>

                <Card p={4} mt={5} flex={"1 0 0"} minW={"450px"}>
                    <Heading>Placeholder</Heading>
                </Card>

                <Card p={4} mt={5} flex={"1 0 0"} minW={"450px"}>
                    <Heading>Placeholder</Heading>
                </Card>

                <Card p={4} mt={5} flex={"1 0 0"} minW={"450px"}>
                    <Heading>Placeholder</Heading>
                </Card>

                <Box minW={"75%"} />
            </HStack>


            <Divider mt={8}/>

            <SimpleGrid minChildWidth={"450px"} w="100%" spacing={10} mt={4}>
                <Card p={4} maxH={"80%"} overflow={"scroll"} >
                    <Heading size="md" mt={5}>
                        Device Details
                    </Heading>
                    <TableContainer>
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
                    </TableContainer>
                </Card>

                <Card p={4} maxH={"80%"} overflow={"scroll"} overflowX={"scroll"}>
                    <Heading size="md" mt={5}>
                        Advanced Device Commands
                    </Heading>
                    <Box mt={"0.25rem"}>{renderCommandsBySection()}</Box>
                </Card>

                <Card p={4} maxH={"80%"} overflow={"scroll"} overflowX={"scroll"}>
                    <WebhookEvents udid={device.UDID}/>
                </Card>
            </SimpleGrid>

            <Modal isOpen={isOpen} onClose={onClose}>
                <ModalOverlay/>
                <ModalContent>
                    <ModalHeader>Send {selectedCommand?.friendlyName}</ModalHeader>
                    <ModalCloseButton/>
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
