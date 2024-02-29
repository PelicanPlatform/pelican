const stringToTime = (time: string) => {
    return new Date(Date.parse(time)).toLocaleString()
}
