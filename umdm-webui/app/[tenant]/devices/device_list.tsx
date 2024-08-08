'use client';

import React, {useEffect, useState} from 'react';
import {
    Box,
    Button,
    Checkbox, FormControl, FormLabel,
    Heading,
    HStack,
    Input,
    Menu,
    MenuButton,
    MenuItem,
    MenuList, Modal, ModalBody, ModalCloseButton, ModalContent, ModalFooter, ModalHeader, ModalOverlay,
    Select, Spacer,
    Spinner,
    Tab,
    Table,
    TabList,
    TabPanel,
    TabPanels,
    Tabs,
    Tbody,
    Td,
    Text,
    Th,
    Thead,
    Tr, useColorModeValue,
    useDisclosure, useToast,
    VStack
} from '@chakra-ui/react';
import {Device, device_queries, DeviceShard, getAllDeviceDetails, getDevices} from '@/lib/micromdm';
import {useParams, useRouter} from 'next/navigation';
import {
    ColumnDef,
    ColumnOrderState,
    createColumnHelper,
    flexRender,
    getCoreRowModel,
    getFilteredRowModel,
    getPaginationRowModel,
    getSortedRowModel,
    useReactTable,
} from '@tanstack/react-table';
import {ChevronDownIcon} from '@chakra-ui/icons';
import CenterCard from "@/app/components/CenterCard";
import commands from "@/lib/commands.json";

const bulkCommands = commands.filter((command: { name: string; }) =>
    ['DeviceInformation', 'InstallProfile', 'RemoveProfile', 'EraseDevice', 'RestartDevice'].includes(command.name)
);

const savePageSizeToLocalStorage = (pageSize: number) => {
    localStorage.setItem('pageSize', pageSize.toString());
};

const loadPageSizeFromLocalStorage = (): number => {
    const savedPageSize = localStorage.getItem('pageSize');
    return savedPageSize ? parseInt(savedPageSize, 10) : 20; // Default to 20 if not found
};

const DeviceList: React.FC = () => {
    const [devices, setDevices] = useState<DeviceShard[]>([]);
    const [allDevices, setAllDevices] = useState<Device[]>([]);
    const [loading, setLoading] = useState<boolean>(true);
    const [globalFilter, setGlobalFilter] = useState<string>('');
    const [columnOrder, setColumnOrder] = useState<ColumnOrderState>([]);
    const [columnVisibility, setColumnVisibility] = useState({});
    const [pageIndex, setPageIndex] = useState(0);
    const [pageSize, setPageSize] = useState<number>(loadPageSizeFromLocalStorage());
    const [selectedDevices, setSelectedDevices] = useState<string[]>([]);
    const [bulkCommand, setBulkCommand] = useState<string>('');
    const { isOpen, onOpen, onClose } = useDisclosure();
    const [selectedCommand, setSelectedCommand] = useState<any>(null);
    const [commandParams, setCommandParams] = useState<any>({});


    const rowHoverBg = useColorModeValue('gray.100', 'gray.700');
    const rowActiveBg = useColorModeValue('gray.200', 'gray.600');

    const router = useRouter();
    const {tenant} = useParams() as { tenant: string; };
    const toast = useToast();

    useEffect(() => {
        savePageSizeToLocalStorage(pageSize);
    }, [pageSize]);

    useEffect(() => {
        const fetchDevices = async () => {
            try {
                const devices = await getDevices(tenant);
                setDevices(devices);
                const allDeviceDetails = await getAllDeviceDetails(tenant);
                setAllDevices(allDeviceDetails);
                return;
            } catch (error) {
                console.error('Error fetching devices:', error);
            } finally {
                setLoading(false);
            }
        };

        if (tenant) {
            fetchDevices();
        }
    }, [tenant]);

    const columnHelperShard = createColumnHelper<DeviceShard>();
    // yes this is bad, but I don't think that there's anything that I can really do about it.
    const columns: ColumnDef<DeviceShard>[] = [
        // @ts-ignore
        columnHelperShard.display({
            id: 'select',
            // @ts-ignore
            header: ({ table }) => (
                <Checkbox
                    isChecked={table.getIsAllRowsSelected()}
                    isIndeterminate={table.getIsSomeRowsSelected()}
                    onChange={table.getToggleAllRowsSelectedHandler()}
                />
            ),
            // @ts-ignore
            cell: ({ row }) => (
                <Checkbox
                    isChecked={row.getIsSelected()}
                    onChange={(e) => {
                        row.getToggleSelectedHandler()(e);
                        e.stopPropagation();
                    }}
                />
            ),
        }),
        // @ts-ignore
        columnHelperShard.accessor('UDID', {
            header: 'UDID',
        }),
        // @ts-ignore
        columnHelperShard.accessor('serial_number', {
            header: 'Serial Number',
        }),
        // @ts-ignore
        columnHelperShard.accessor('model', {
            header: 'Model',
        }),
        // @ts-ignore
        columnHelperShard.display({
            id: 'actions',
            cell: ({ row }) => (
                <Button size="sm" onClick={() => router.push(`/${tenant}/devices/details/${row.original.UDID}`)}>
                    Details
                </Button>
            ),
        }),
    ];

    const columnHelperDevice = createColumnHelper<Device>();
    const allDeviceColumns: ColumnDef<Device>[] = [
        // @ts-ignore
        columnHelperShard.display({
            id: 'select',
            // @ts-ignore
            header: ({ table }) => (
                <Checkbox
                    isChecked={table.getIsAllRowsSelected()}
                    isIndeterminate={table.getIsSomeRowsSelected()}
                    onChange={table.getToggleAllRowsSelectedHandler()}
                />
            ),
            // @ts-ignore
            cell: ({ row }) => (
                <Checkbox
                    isChecked={row.getIsSelected()}
                    onChange={(e) => {
                        row.getToggleSelectedHandler()(e);
                        e.stopPropagation();
                    }}
                />
            ),
        }),
        // @ts-ignore
        columnHelperDevice.accessor('SerialNumber', {
            header: 'Serial Number',
        }),
        // @ts-ignore
        columnHelperDevice.accessor('DeviceName', {
            header: 'Device Name',
        }),
        // @ts-ignore
        columnHelperDevice.accessor('ProductName', {
            header: 'Product Identifier',
        }),
        // @ts-ignore
        columnHelperDevice.accessor('Model', {
            header: 'Model',
        }),
        // @ts-ignore
        columnHelperDevice.accessor('OSVersion', {
            header: 'OS Version',
        }),
        // @ts-ignore
        columnHelperDevice.accessor('UDID', {
            header: 'UDID',
        }),
        // @ts-ignore
        columnHelperShard.display({
            id: 'actions',
            cell: ({ row }) => (
                <Button size="sm" onClick={() => router.push(`/${tenant}/devices/details/${row.original.UDID}`)}>
                    Details
                </Button>
            ),
        }),
    ];

    const mdmTable = useReactTable({
        data: devices,
        columns,
        state: {
            columnOrder,
            columnVisibility,
            globalFilter,
            pagination: { pageIndex, pageSize },
        },
        onPaginationChange: setState => {
            if (typeof setState === 'function') {
                const newState = setState({ pageIndex, pageSize });
                setPageIndex(newState.pageIndex);
                setPageSize(newState.pageSize);
            }
        },
        onColumnOrderChange: setColumnOrder,
        onColumnVisibilityChange: setColumnVisibility,
        onGlobalFilterChange: setGlobalFilter,
        getCoreRowModel: getCoreRowModel(),
        getSortedRowModel: getSortedRowModel(),
        getPaginationRowModel: getPaginationRowModel(),
        getFilteredRowModel: getFilteredRowModel(),
    });

    const allDevicesTable = useReactTable({
        data: allDevices,
        columns: allDeviceColumns,
        state: {
            columnOrder,
            columnVisibility,
            globalFilter,
            pagination: { pageIndex, pageSize },
        },
        onPaginationChange: setState => {
            if (typeof setState === 'function') {
                const newState = setState({ pageIndex, pageSize });
                setPageIndex(newState.pageIndex);
                setPageSize(newState.pageSize);
            }
        },
        onColumnOrderChange: setColumnOrder,
        onColumnVisibilityChange: setColumnVisibility,
        onGlobalFilterChange: setGlobalFilter,
        getCoreRowModel: getCoreRowModel(),
        getSortedRowModel: getSortedRowModel(),
        getPaginationRowModel: getPaginationRowModel(),
        getFilteredRowModel: getFilteredRowModel(),
    });

    const handleBulkCommand = async () => {
        if (!selectedCommand) {
            toast({
                title: "Please select a command",
                status: "warning",
                duration: 3000,
                isClosable: true,
            });
            return;
        }

        // Use the active table (either allDevicesTable or mdmTable)
        const activeTable = allDevicesTable.getSelectedRowModel().rows.length > 0 ? allDevicesTable : mdmTable;
        const selectedUDIDs = activeTable.getSelectedRowModel().rows.map(row => row.original.UDID);

        if (selectedUDIDs.length === 0) {
            toast({
                title: "No devices selected",
                status: "warning",
                duration: 3000,
                isClosable: true,
            });
            return;
        }

        try {
            let command;
            if (selectedCommand.name === 'DeviceInformation') {
                command = {
                    request_type: 'DeviceInformation',
                    queries: device_queries
                };
            } else {
                command = {
                    request_type: selectedCommand.name,
                    ...commandParams,
                };
            }

            const response = await fetch(`/${tenant}/api/commands/bulk`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({command, udids: selectedUDIDs}),
            });

            if (!response.ok) {
                throw new Error('Failed to send bulk command');
            }

            const data = await response.json();
            console.log('Bulk command response:', data);

            toast({
                title: `Bulk ${selectedCommand.friendlyName} command sent successfully to ${selectedUDIDs.length} devices`,
                status: "success",
                duration: 5000,
                isClosable: true,
            });

            onClose();
            setSelectedCommand(null);
            setCommandParams({});
        } catch (error) {
            const err = error as Error;
            console.error('Error sending bulk command:', err);
            toast({
                title: "Error sending bulk command",
                description: err.message,
                status: "error",
                duration: 5000,
                isClosable: true,
            });
        }
    }

    const BulkCommandModal = () => (
        <Modal isOpen={isOpen} onClose={onClose}>
            <ModalOverlay />
            <ModalContent>
                <ModalHeader>Bulk Command: {selectedCommand?.friendlyName}</ModalHeader>
                <ModalCloseButton />
                <ModalBody>
                    <FormControl>
                        <FormLabel>Command</FormLabel>
                        <Select
                            value={selectedCommand?.name || ''}
                            onChange={(e) => {
                                const command = bulkCommands.find(cmd => cmd.name === e.target.value);
                                setSelectedCommand(command);
                                setCommandParams({});
                            }}
                        >
                            <option value="">Select a command</option>
                            {bulkCommands.map(command => (
                                <option key={command.name} value={command.name}>
                                    {command.friendlyName}
                                </option>
                            ))}
                        </Select>
                    </FormControl>
                    {selectedCommand && renderCommandParams()}
                </ModalBody>
                <ModalFooter>
                    <Button colorScheme="blue" mr={3} onClick={handleBulkCommand}>
                        Send Command
                    </Button>
                    <Button variant="ghost" onClick={onClose}>Cancel</Button>
                </ModalFooter>
            </ModalContent>
        </Modal>
    );

    const renderCommandParams = () => {
        if (!selectedCommand || !selectedCommand.parameters || selectedCommand.name === 'DeviceInformation') return null;

        return Object.entries(selectedCommand.parameters).map(([key, param]: [string, any]) => (
            <FormControl key={key} mt={4}>
                <FormLabel>{param.description}</FormLabel>
                <Input
                    placeholder={`Enter ${key}`}
                    onChange={(e) => setCommandParams({...commandParams, [key]: e.target.value})}
                />
            </FormControl>
        ));
    };

    if (loading) {
        return (
            <>
                <Spinner/>
            </>
        );
    } else if (!allDevices) {
        return (
            <>
                <CenterCard>
                    <Heading>No devices have responded to requests for information.</Heading>
                    <Text>Not what you&apos;re expecting to see?</Text>
                    <Text>Check your profiles and network connections on each device.</Text>
                </CenterCard>
            </>
        )
    }

    // @ts-ignore
    const renderColumnToggle = (table: any) => (
        <Menu>
            <MenuButton as={Button} rightIcon={<ChevronDownIcon/>}>
                Toggle Columns
            </MenuButton>
            <MenuList>
                {
                    // @ts-ignore
                    table.getAllLeafColumns().map(column => (
                        <MenuItem key={column.id}>
                            <Checkbox
                                isChecked={column.getIsVisible()}
                                onChange={column.getToggleVisibilityHandler()}
                            >
                                {column.id}
                            </Checkbox>
                        </MenuItem>
                    ))}
            </MenuList>
        </Menu>
    );

    // @ts-ignore
    const PaginationControls = ({ table }) => {
        return (
            <HStack spacing={4} mt={4}>
                <Button
                    onClick={() => table.setPageIndex(0)}
                    isDisabled={!table.getCanPreviousPage()}
                >
                    {'<<'}
                </Button>
                <Button
                    onClick={() => table.previousPage()}
                    isDisabled={!table.getCanPreviousPage()}
                >
                    {'<'}
                </Button>
                <Button
                    onClick={() => table.nextPage()}
                    isDisabled={!table.getCanNextPage()}
                >
                    {'>'}
                </Button>
                <Button
                    onClick={() => table.setPageIndex(table.getPageCount() - 1)}
                    isDisabled={!table.getCanNextPage()}
                >
                    {'>>'}
                </Button>
                <Text>
                    Page {table.getState().pagination.pageIndex + 1} of{' '}
                    {table.getPageCount()}
                </Text>
                <Select
                    value={table.getState().pagination.pageSize}
                    onChange={e => {
                        const newSize = Number(e.target.value);
                        table.setPageSize(newSize);
                        savePageSizeToLocalStorage(newSize);
                    }}
                >
                    {[20, 50, 100].map(pageSize => (
                        <option key={pageSize} value={pageSize}>
                            Show {pageSize}
                        </option>
                    ))}
                    <option value={table.getPrePaginationRowModel().rows.length}>
                        Show All
                    </option>
                </Select>
            </HStack>
        );
    };

    return (
        <Box>
            {/*<Heading as="h1" size="lg" mb={4}>Device List</Heading>*/}
            <Tabs>
                <TabList>
                    <Tab>Checked-in Devices</Tab>
                    <Tab>MDM Devices</Tab>
                </TabList>

                <TabPanels>
                    <TabPanel>
                        <VStack align="start" mb={4}>
                            <HStack w={"100%"} spacing={4}>
                                <Input
                                    placeholder="Search..."
                                    value={globalFilter ?? ''}
                                    onChange={e => setGlobalFilter(e.target.value)}
                                />
                                {renderColumnToggle(allDevicesTable)}
                                <Button
                                    onClick={() => {
                                        setSelectedCommand(null);
                                        setCommandParams({});
                                        onOpen();
                                    }}
                                    isDisabled={allDevicesTable.getSelectedRowModel().rows.length === 0}
                                >
                                    Bulk Command
                                </Button>
                            </HStack>
                            <Table>
                                <Thead>
                                    {allDevicesTable.getHeaderGroups().map(headerGroup => (
                                        <Tr key={headerGroup.id}>
                                            {headerGroup.headers.map(header => (
                                                <Th key={header.id}>
                                                    {header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
                                                </Th>
                                            ))}
                                        </Tr>
                                    ))}
                                </Thead>
                                <Tbody>
                                    {allDevicesTable.getRowModel().rows.map(row => (
                                        <Tr
                                            key={row.id}
                                            _hover={{ bg: rowHoverBg }}
                                            _active={{ bg: rowActiveBg }}
                                            cursor="pointer"
                                        >
                                            {row.getVisibleCells().map(cell => (
                                                <Td key={cell.id}>
                                                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                                                </Td>
                                            ))}
                                        </Tr>
                                    ))}
                                </Tbody>
                            </Table>
                        </VStack>
                        <PaginationControls table={allDevicesTable} />

                    </TabPanel>

                    {/* MDM Devices Tab */}
                    <TabPanel>
                        <VStack align="start" mb={2}>
                            <HStack w={"100%"} spacing={4}>
                                <Input
                                    placeholder="Search..."
                                    value={globalFilter ?? ''}
                                    onChange={e => setGlobalFilter(e.target.value)}
                                />
                                {renderColumnToggle(mdmTable)}
                                <Button
                                    onClick={() => {
                                        setSelectedCommand(null);
                                        setCommandParams({});
                                        onOpen();
                                    }}
                                    isDisabled={mdmTable.getSelectedRowModel().rows.length === 0}
                                >
                                    Bulk Command
                                </Button>
                            </HStack>
                            <Table>
                                <Thead>
                                    {mdmTable.getHeaderGroups().map(headerGroup => (
                                        <Tr key={headerGroup.id}>
                                            {headerGroup.headers.map(header => (
                                                <Th key={header.id}>
                                                    {header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
                                                </Th>
                                            ))}
                                        </Tr>
                                    ))}
                                </Thead>
                                <Tbody>
                                    {mdmTable.getRowModel().rows.map(row => (
                                        <Tr
                                            key={row.id}
                                            _hover={{ bg: rowHoverBg }}
                                            _active={{ bg: rowActiveBg }}
                                            cursor="pointer"
                                        >
                                            {row.getVisibleCells().map(cell => (
                                                <Td key={cell.id}>
                                                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                                                </Td>
                                            ))}
                                        </Tr>
                                    ))}
                                </Tbody>
                            </Table>
                        </VStack>
                        <PaginationControls table={mdmTable} />
                    </TabPanel>
                </TabPanels>
            </Tabs>
            <BulkCommandModal />
        </Box>
    );
};

export default DeviceList;
