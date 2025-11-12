const createdRecently = (createdAt: number) => {
  return new Date().getTime() - createdAt < 1000 * 60 * 60 * 1;
};

export default createdRecently;
