function a11yProps(index: number, prefix: string = 'simple') {
  return {
    id: `${prefix}-tab-${index}`,
    'aria-controls': `${prefix}-tabpanel-${index}`,
  };
}

export default a11yProps;
