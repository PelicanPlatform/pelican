"use client"

import Image from 'next/image'

import {Box, Button, ButtonProps, Grid, Typography} from "@mui/material";
import { TextField } from '@mui/material';

import {Header} from "@/components/layout/Header";
import ProgressPager from "@/components/progress-pager";
import styles from './page.module.css'
import {useRef, useState, ClipboardEvent, ChangeEvent, KeyboardEvent} from "react";

interface CodeInputProps {
    length: number;
    submitFunction?: () => void;
}

function CodeInput({length, submitFunction}: CodeInputProps) {

    const inputRefs = useRef<HTMLInputElement[] | null[] | never[]>([])

    function setCode(code: number[], offset: number) {

        if(code.length == length){
            offset = 0
        }

        Array.from(Array(code.length).keys()).forEach(index => {
            if(index + offset < inputRefs.current.length) {
                inputRefs.current[index + offset]!.value = code[index].toString()
            }
        })
    }

    const onChange = (e: ChangeEvent, index: number) => {

        if(index >= inputRefs.current.length - 1) {
            return
        }

        const currentInput = inputRefs.current[index]
        const nextInput = inputRefs.current[index + 1]

        if (!Number.isInteger(Number(currentInput!.value))) {
            currentInput!.value = ""
            return
        }

        nextInput!.focus()
    }

    const onPaste = (e: ClipboardEvent, index: number) => {
        let code = e.clipboardData.getData('Text').split("").map(x => Number(x))

        setCode(code, index)
    }

    const onKeyDown = (e: KeyboardEvent, index: number) => {

        if(["Backspace"].includes(e.code)) {

            const currentInput = inputRefs.current[index]

            if(index == 0) {
                currentInput!.value = ""

            } else {
                const previousInput = inputRefs.current[index - 1]

                if(currentInput!.value == "") {
                    previousInput!.focus()

                } else {
                    currentInput!.value = ""

                }
            }

            e.preventDefault()
        }
    }

    return (
        <Grid container spacing={1}>
            {
                Array.from(Array(length).keys()).map((index) => {

                    return (
                        <Grid item key={index} textAlign={"center"}>
                            <TextField
                                inputProps={{
                                    sx: {
                                        width: "50px",
                                        borderWidth: "3px",
                                        fontSize: "3rem",
                                        textAlign: "center",
                                        padding: ".5rem",
                                        backgroundColor: "secondary.main",
                                    },
                                    maxLength: 1,
                                    ref: (el : HTMLInputElement) => inputRefs.current[index] = el
                                }}
                                variant="outlined"
                                onKeyDown={(e) => onKeyDown(e, index)}
                                onChange={(e) => onChange(e, index)}
                                onPaste={(e) => onPaste(e, index)}
                            />
                        </Grid>
                    )
                })
            }
        </Grid>
    )

}

function LoadingButton<ButtonProps> ({...props}) {

        const [loading, setLoading] = useState(false);

        function handleClick() {
            setLoading(true);
            console.log(loading)
        }

        if(loading){
            return (
                <Button
                    onClick={handleClick}
                    variant="outlined"
                    disabled={loading}
                    {...props}
                >
                    <span>Activate</span>
                </Button>
            )
        }

        return (
            <Button
                onClick={handleClick}
                variant="outlined"
                {...props}
            >
                <span>Activate</span>
            </Button>
        )
}

function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault()

    console.log

}

export default function Home() {

    return (
        <>
            <Box m={"auto"} mt={12}  display={"flex"} flexDirection={"column"}>
                <Box>
                    <Typography textAlign={"center"} variant={"h3"} component={"h3"}>
                        Activate Origin Website
                    </Typography>
                    <Typography textAlign={"center"} variant={"h6"} component={"p"}>
                        Enter the activation code displayed on the command line
                    </Typography>
                </Box>
                <Box pt={3} mx={"auto"}>
                    <form onSubmit={submit}>
                        <CodeInput length={6}/>
                        <Box mt={3} display={"flex"}>
                            <LoadingButton
                                variant="outlined"
                                style={{margin: "auto"}}
                            >
                                <span>Activate</span>
                            </LoadingButton>
                        </Box>
                    </form>

                </Box>
            </Box>
        </>
    )
}
