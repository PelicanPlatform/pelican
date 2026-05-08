const dateSort = (a: string, b: string) => {
  const dateA = new Date(a);
  const dateB = new Date(b);

  if (isNaN(dateA.getTime()) && isNaN(dateB.getTime())) {
    return 0; // Both are invalid dates, consider them equal
  } else if (isNaN(dateA.getTime())) {
    return -1; // a is an invalid date, consider it less than b
  } else if (isNaN(dateB.getTime())) {
    return 1; // b is an invalid date, consider it less than a
  }

  return dateA.getTime() - dateB.getTime();
};

export default dateSort;
