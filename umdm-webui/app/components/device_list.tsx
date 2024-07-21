'use client';

import React, { useEffect, useState } from 'react';
import {
  Box,
  Heading,
  Spinner,
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
  Table,
  Tbody,
  Td,
  Th,
  Thead,
  Tr,
  Input,
  Checkbox,
  VStack,
  HStack,
  Button,
  Menu,
  MenuButton,
  MenuList,
  MenuItem
} from '@chakra-ui/react';
import { getDevices, getAllDeviceDetails, DeviceShard, Device } from '@/lib/micromdm';
import { useRouter } from 'next/navigation';
import {
  useReactTable,
  createColumnHelper,
  getCoreRowModel,
  getSortedRowModel,
  getPaginationRowModel,
  getFilteredRowModel,
  ColumnDef,
  flexRender,
  ColumnOrderState,
} from '@tanstack/react-table';
import { ChevronDownIcon } from '@chakra-ui/icons';

const DeviceList: React.FC = () => {
  const [devices, setDevices] = useState<DeviceShard[]>([]);
  const [allDevices, setAllDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [globalFilter, setGlobalFilter] = useState<string>('');
  const [columnOrder, setColumnOrder] = useState<ColumnOrderState>([]);
  const [columnVisibility, setColumnVisibility] = useState({});

  const router = useRouter();

  useEffect(() => {
    const fetchDevices = async () => {
      const devices = await getDevices();
      setDevices(devices);
      const allDeviceDetails = await getAllDeviceDetails();
      setAllDevices(allDeviceDetails);
      setLoading(false);
    };

    fetchDevices();
  }, []);

  const columnHelperShard = createColumnHelper<DeviceShard>();
  const columns: ColumnDef<DeviceShard>[] = [
    columnHelperShard.accessor('udid', {
      header: 'UUID',
    }),
    columnHelperShard.accessor('serial_number', {
      header: 'Serial Number',
    }),
    columnHelperShard.accessor('model', {
      header: 'Model',
    }),
  ];

  const columnHelperDevice = createColumnHelper<Device>();
  const allDeviceColumns: ColumnDef<Device>[] = [
    columnHelperDevice.accessor('SerialNumber', {
      header: 'Serial Number',
    }),
    columnHelperDevice.accessor('DeviceName', {
      header: 'Device Name',
    }),
    columnHelperDevice.accessor('ProductName', {
      header: 'Product Identifierr',
    }),
    columnHelperDevice.accessor('Model', {
      header: 'Model',
    }),
    columnHelperDevice.accessor('OSVersion', {
      header: 'OS Version',
    }),
    columnHelperDevice.accessor('UDID', {
      header: 'UDID',
    }),
  ];

  const mdmTable = useReactTable({
    data: devices,
    columns,
    state: {
      columnOrder,
      columnVisibility,
      globalFilter,
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
    },
    onColumnOrderChange: setColumnOrder,
    onColumnVisibilityChange: setColumnVisibility,
    onGlobalFilterChange: setGlobalFilter,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
  });

  if (loading) {
    return <Spinner />;
  }

  const renderColumnToggle = (table: any) => (
    <Menu>
      <MenuButton as={Button} rightIcon={<ChevronDownIcon />}>
        Toggle Columns
      </MenuButton>
      <MenuList>
        {table.getAllLeafColumns().map(column => (
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

  return (
    <Box>
      <Heading as="h1" size="lg" mb={4}>Device List</Heading>
      <Tabs>
        <TabList>
          <Tab>Checked-in Devices</Tab>
          <Tab>MDM Devices</Tab>
        </TabList>

        <TabPanels>
          <TabPanel>
            <VStack align="start" mb={4}>
              <HStack>
                <Input
                  placeholder="Search..."
                  value={globalFilter ?? ''}
                  onChange={e => setGlobalFilter(e.target.value)}
                />
                {renderColumnToggle(allDevicesTable)}
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
                    <Tr key={row.id} onClick={() => router.push(`/devices/details/${row.original.UDID}`)}>
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
          </TabPanel>
          
          {/* MDM Devices Tab */ }
          <TabPanel>
            <VStack align="start" mb={4}>
              <HStack >
                <Input
                  placeholder="Search..."
                  value={globalFilter ?? ''}
                  onChange={e => setGlobalFilter(e.target.value)}
                />
                {renderColumnToggle(mdmTable)}
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
                    <Tr key={row.id} onClick={() => router.push(`/devices/details/${row.original.udid}`)}>
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
          </TabPanel>
        </TabPanels>
      </Tabs>
    </Box>
  );
};

export default DeviceList;
