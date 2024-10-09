import React from 'react';
import Markdown from 'react-markdown';
import { useTheme } from '@mui/material';
import { Typography, List, ListItem, Box } from '@mui/material';
import SyntaxHighlighter from 'react-syntax-highlighter';
import { stackoverflowLight } from 'react-syntax-highlighter/dist/cjs/styles/hljs';


const MarkdownRender: React.FC<{ content: string }> = ({ content }) => {
    const theme = useTheme();

    // Define components directly within the components prop to ensure type alignment
    return (
        <Markdown
            components={{
                // Inline code
                code: ({className, children, ...props}) => {
                    const match = /language-(\w+)/.exec(className || '')
                    // Define inline code style
                    const inlineStyle: React.CSSProperties = {
                        fontFamily: "ui-monospace, monospace",
                        fontWeight: "400",
                        fontSize: '.9em',
                        backgroundColor: theme.palette.mode == "dark" ? '#19222d' : 'rgba(0,0,0,0.03)',
                        borderWidth: '1px',
                        borderColor: 'rgba(0,0,0.0.04)',
                        borderRadius: '0.375rem',
                        padding: '.125rem .25em .125rem .25em',
                        color: theme.palette.mode == "dark" ? "#e5f0fe" : 'rgba(51,65,85,1)',
                    };

                    // If it has no language tag, it's inline code
                    if (!match) {
                        return <code style={inlineStyle} {...props}>{children}</code>;
                    }
                    // For code blocks
                    return (
                        <SyntaxHighlighter
                            PreTag="div"
                            language={match[1]}
                            style={stackoverflowLight}
                            customStyle={{background: ""}}
                            codeTagProps={{style: {display: "inline"}}}
                            wrapLines
                        >
                          {String(children).replace(/\n$/, '')}
                        </SyntaxHighlighter>
                    )
                },
                // Block-level code
                pre: ({children, ...props}) => {
                    // Define block-level code style
                    const blockStyle: React.CSSProperties = {
                        contain: "paint",
                        fontSize: '.9em',
                        color: 'rgb(51, 65, 85)',
                        fontFamily: "ui-monospace, monospace",
                        fontWeight: "400",
                        backgroundColor: theme.palette.mode == "dark" ? '#19222d' : 'rgba(0, 93, 199, 0.05)',
                        borderColor: "rgb(229, 231, 235)",
                        borderRadius: '12px',
                        padding: '1rem',
                        overflowX: 'auto',
                        margin: '10px 0',
                    };
                    return <pre style={blockStyle} {...props}>{children}</pre>;
                },
                img: ({src, alt}) => <img style={{maxWidth: "100%", height: "auto"}} src={src} alt={alt} />,
                li: ({children}) => <ListItem disablePadding sx={{display:"list-item"}}>{children}</ListItem>,
                ul: ({children}) => <List sx={{ listStyleType: 'disc' }} style={{paddingLeft: "1rem"}}>{children}</List>,
                a: ({children, href}) => {
                    const aStyle: React.CSSProperties = {
                        color: "rgb(0, 107, 230)",
                        textDecorationLine: "underline",
                        textDecorationThickness: "from-font",
                    };

                    return <Typography component="a" href={href} style={aStyle} target='_blank' >{children}</Typography>
                },
                strong: ({children}) => <Box component="span" display="inline" fontWeight="bold">{children}</Box>,
                text: ({ children }) => <Typography variant="body1" display="inline">{children}</Typography>,
                div: ({children}) => <Box>{children}</Box>,
            }}
        >
          {content}
        </Markdown>
    )
};

export interface CodeBlockProps {
  className?: string;
  children: React.ReactNode;
}

export interface PreProps {
  children: React.ReactNode;
}

export default MarkdownRender;
