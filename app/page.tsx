'use client';

import { useState, useRef, useEffect, useCallback } from 'react';
import ReactMarkdown from 'react-markdown';

interface Message {
  role: 'user' | 'assistant';
  content: string;
  reasoning?: string;
}

interface Model {
  id: string;
  object: string;
  created?: number;
  owned_by?: string;
}

interface ExtraParameter {
  displayName: string;
  paramName: string;
  value: string;
}

// Parse parameters from environment variable
const parseExtraParameters = (): ExtraParameter[] => {
  const paramString = process.env.NEXT_PUBLIC_EXTRA_PARAMETERS || '';
  return paramString.split(';')
    .filter(Boolean)
    .map(param => {
      const [displayName, paramValue] = param.split(':');
      const [paramName, value] = paramValue.split('=');
      return { displayName, paramName, value };
    });
};

export default function Home() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isStreaming, setIsStreaming] = useState(false);
  const [models, setModels] = useState<Model[]>([]);
  const [selectedModel, setSelectedModel] = useState<string>("")
  const [isLoadingModels, setIsLoadingModels] = useState(true);
  const [apiKey, setApiKey] = useState('');
  const [extraParams, setExtraParams] = useState<ExtraParameter[]>(parseExtraParameters());
  const [isParamMenuOpen, setIsParamMenuOpen] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Check if streaming is enabled
  const isStreamingEnabled = process.env.NEXT_PUBLIC_STREAM === 'true';

  // Read API key from URL on component mount
  useEffect(() => {
    const searchParams = new URLSearchParams(window.location.search);
    const apiKeyFromUrl = searchParams.get('key');
    if (apiKeyFromUrl) {
      setApiKey(apiKeyFromUrl);
    }
    const model = searchParams.get('model');
    if (model) {
      setSelectedModel(model);
    }
  }, []);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const fetchModels = useCallback(async () => {
    try {
      const response = await fetch('/v1/models');
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      setModels(data.data || []);
      // Only set model if not set or current model doesn't exist in list
      if (data.data && data.data.length > 0) {
        const modelIds = data.data.map((model: Model) => model.id);
        if (!selectedModel || !modelIds.includes(selectedModel)) {
          setSelectedModel(data.data[0].id);
        }
      }
    } catch (error) {
      console.error('Error fetching models:', error);
    } finally {
      setIsLoadingModels(false);
    }
  }, [selectedModel]);

  // Fetch available models on component mount
  useEffect(() => {
    fetchModels();
  }, [fetchModels]);

  const sendMessage = async () => {
    if (!input.trim() || isLoading || isStreaming) return;

    const userMessage: Message = { role: 'user', content: input };
    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);
    
    // Check if streaming is enabled
    const isStreamingEnabled = process.env.NEXT_PUBLIC_STREAM === 'true';
    
    if (isStreamingEnabled) {
      setIsStreaming(true);
      // Add an empty assistant message that we'll update as we stream
      const assistantMessage: Message = { role: 'assistant', content: '' };
      setMessages(prev => [...prev, assistantMessage]);
    }

    try {
      const headers: HeadersInit = {
        'Content-Type': 'application/json',
      };
      
      if (apiKey.trim()) {
        headers['Authorization'] = `Bearer ${apiKey.trim()}`;
      }

      // Convert extra parameters to request body
      const extraParamsBody = extraParams.reduce((acc, param) => ({
        ...acc,
        [param.paramName]: param.value
      }), {});

      const response = await fetch(`${process.env.NEXT_PUBLIC_API_BASE || ''}/v1/chat/completions`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          model: selectedModel,
          messages: [...messages, userMessage],
          stream: isStreamingEnabled, // Enable streaming only if configured
          ...extraParamsBody
        }),
      });

      if (!response.ok) {
        let errorMessage = 'Sorry, I encountered an error while processing your request. Please try again.';
        
        const errorData = await response.json();
        const serverError = errorData.error || '';
        
        if (response.status === 401) {
          if (serverError.includes('Authorization header required')) {
            errorMessage = '🔑 API key required. Please enter your API key in the header above.';
          } else if (serverError.includes('Invalid API key')) {
            errorMessage = '🔑 Invalid API key. Please check your API key and try again.';
          } else if (serverError.includes('Invalid authorization format')) {
            errorMessage = '🔑 API key format error. This shouldn\'t happen - please refresh the page.';
          } else {
            errorMessage = `🔑 Authentication failed: ${serverError}`;
          }
        } else if (response.status === 400 && serverError.includes('Authorization')) {
          errorMessage = `🔑 API key error: ${serverError}`;
        } else if (serverError) {
          errorMessage = `Error: ${serverError}`;
        } else {
          errorMessage = `HTTP error! status: ${response.status}`;
        }
        
        if (isStreamingEnabled) {
          // Update the assistant message with the error
          setMessages(prev => {
            const newMessages = [...prev];
            newMessages[newMessages.length - 1] = {
              role: 'assistant',
              content: errorMessage,
            };
            return newMessages;
          });
        } else {
          // Add error message for non-streaming
          const assistantErrorMessage: Message = {
            role: 'assistant',
            content: errorMessage,
          };
          setMessages(prev => [...prev, assistantErrorMessage]);
        }
        return;
      }

      if (isStreamingEnabled) {
        // Handle streaming response
        const reader = response.body?.getReader();
        const decoder = new TextDecoder();
        let accumulatedContent = '';
        let accumulatedReasoning = '';

        if (reader) {
          try {
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;

              const chunk = decoder.decode(value);
              const lines = chunk.split('\n');

              for (const line of lines) {
                if (line.startsWith('data: ')) {
                  const data = line.slice(6);
                  
                  if (data === '[DONE]') {
                    // Stream finished
                    break;
                  }

                  try {
                    const parsed = JSON.parse(data);
                    const delta = parsed.choices?.[0]?.delta;
                    
                    if (delta) {
                      // Handle content streaming
                      if (delta.content) {
                        accumulatedContent += delta.content;
                      }
                      
                      // Handle reasoning streaming (if supported by the model)
                      if (delta.reasoning) {
                        accumulatedReasoning += delta.reasoning;
                      }
                      
                      // Update the assistant message with all accumulated content
                      setMessages(prev => {
                        const newMessages = [...prev];
                        newMessages[newMessages.length - 1] = {
                          role: 'assistant',
                          content: accumulatedContent,
                          reasoning: accumulatedReasoning || undefined,
                        };
                        return newMessages;
                      });
                    }
                  } catch (e) {
                    // Ignore parsing errors for malformed JSON
                    console.warn('Failed to parse streaming data:', e);
                  }
                }
              }
            }
          } finally {
            reader.releaseLock();
          }
        }
      } else {
        // Handle non-streaming response
        const data = await response.json();
        const assistantMessage: Message = {
          role: 'assistant',
          content: data.choices[0].message.content,
          reasoning: data.choices[0].message.reasoning,
        };

        setMessages(prev => [...prev, assistantMessage]);
      }
    } catch (error) {
      console.error('Error calling chat API:', error);
      const errorMessage: Message = {
        role: 'assistant',
        content: 'Sorry, I encountered a network error while processing your request. Please check your connection and try again.',
      };
      
      if (isStreamingEnabled) {
        // Update the assistant message with the error
        setMessages(prev => {
          const newMessages = [...prev];
          newMessages[newMessages.length - 1] = errorMessage;
          return newMessages;
        });
      } else {
        // Add error message for non-streaming
        setMessages(prev => [...prev, errorMessage]);
      }
    } finally {
      setIsLoading(false);
      if (isStreamingEnabled) {
        setIsStreaming(false);
      }
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const clearMessages = () => {
    setMessages([]);
  };

  return (
    <div className="flex flex-col h-screen bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <header className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 px-4 py-2">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          <h1 className="text-lg font-semibold text-gray-800 dark:text-white">
            Chat Assistant
          </h1>
          
          {/* Controls */}
          <div className="flex flex-wrap items-center gap-2 sm:gap-4">
            {/* Model Selector */}
            <div className="flex items-center gap-2">
              <label htmlFor="model-select" className="text-sm font-medium text-gray-700 dark:text-gray-300 hidden sm:inline">
                Model:
              </label>
              {isLoadingModels ? (
                <div className="w-24 h-7 bg-gray-200 dark:bg-gray-700 rounded animate-pulse"></div>
              ) : (
                <select
                  id="model-select"
                  value={selectedModel}
                  onChange={(e) => setSelectedModel(e.target.value)}
                  className="px-2 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent w-24 sm:w-32"
                  disabled={isLoading || (isStreamingEnabled && isStreaming)}
                >
                  {models.map((model) => (
                    <option key={model.id} value={model.id}>
                      {model.id}
                    </option>
                  ))}
                </select>
              )}
              <button
                onClick={fetchModels}
                disabled={isLoadingModels || isLoading || (isStreamingEnabled && isStreaming)}
                className="p-1 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 disabled:opacity-50"
                title="Refresh models"
              >
                <svg className={`w-4 h-4 ${isLoadingModels ? 'animate-spin' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
              </button>
            </div>

            {/* API Key Input */}
            <div className="flex items-center gap-2">
              <label htmlFor="api-key" className="text-sm font-medium text-gray-700 dark:text-gray-300 hidden sm:inline">
                API Key:
              </label>
              <input
                id="api-key"
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="API key"
                className="px-2 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent w-32 sm:w-40"
                disabled={isLoading || (isStreamingEnabled && isStreaming)}
              />
            </div>

            {/* Extra Parameters Menu */}
            <div className="relative">
              <button
                onClick={() => setIsParamMenuOpen(!isParamMenuOpen)}
                className="px-2 py-1 text-sm font-medium text-gray-700 dark:text-gray-300 hover:text-blue-600 dark:hover:text-blue-400 border border-gray-300 dark:border-gray-600 rounded-md hover:border-blue-300 dark:hover:border-blue-600 transition-colors duration-200 disabled:opacity-50"
                title="Extra Parameters"
                disabled={isLoading || (isStreamingEnabled && isStreaming)}
              >
                <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                </svg>
                <span className="hidden sm:inline ml-1">Parameters</span>
              </button>

              {isParamMenuOpen && (
                <div className="absolute right-0 mt-2 w-72 sm:w-96 bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 p-4 sm:p-5 z-50">
                  <div className="flex justify-between items-center mb-4 sm:mb-5">
                    <h3 className="text-base sm:text-lg font-semibold text-gray-900 dark:text-white">Extra Parameters</h3>
                    <button
                      onClick={() => setIsParamMenuOpen(false)}
                      className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
                    >
                      <svg className="w-4 h-4 sm:w-5 sm:h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>
                  <div className="space-y-4 sm:space-y-5">
                    {extraParams.map((param, index) => (
                      <div key={index} className="flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-4">
                        <label className="w-full sm:w-28 text-sm font-medium text-gray-700 dark:text-gray-300">
                          {param.displayName}:
                        </label>
                        <input
                          type="text"
                          value={param.value}
                          onChange={(e) => {
                            const newParams = [...extraParams];
                            newParams[index] = { ...param, value: e.target.value };
                            setExtraParams(newParams);
                          }}
                          className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                          placeholder={`Enter ${param.displayName}`}
                          disabled={isLoading || (isStreamingEnabled && isStreaming)}
                        />
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Clear Messages Button */}
            <button
              onClick={clearMessages}
              disabled={isLoading || (isStreamingEnabled && isStreaming) || messages.length === 0}
              className="px-2 py-1 text-sm font-medium text-gray-700 dark:text-gray-300 hover:text-red-600 dark:hover:text-red-400 border border-gray-300 dark:border-gray-600 rounded-md hover:border-red-300 dark:hover:border-red-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
              title="Clear all messages"
            >
              <svg className="w-4 h-4 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
              </svg>
              <span className="hidden sm:inline ml-1">Clear Chat</span>
            </button>
          </div>
        </div>
      </header>

      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto px-4 py-6">
        <div className="max-w-3xl mx-auto space-y-6">
          {messages.length === 0 && (
            <div className="text-center text-gray-500 dark:text-gray-400 mt-20">
              <div className="text-4xl mb-4">💬</div>
              <h2 className="text-2xl font-semibold mb-2">How can I help you today?</h2>
              <p>Start a conversation by typing a message below.</p>
              {selectedModel && (
                <p className="text-sm mt-2">
                  Using model: <span className="font-mono font-semibold">{selectedModel}</span>
                </p>
              )}
            </div>
          )}
          
          {messages.map((message, index) => (
            <div
              key={index}
              className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              <div
                className={`max-w-xs lg:max-w-md xl:max-w-lg px-4 py-2 rounded-lg ${
                  message.role === 'user'
                    ? 'bg-blue-500 text-white'
                    : 'bg-white dark:bg-gray-800 text-gray-800 dark:text-white border border-gray-200 dark:border-gray-700'
                }`}
              >
                {message.role === 'user' ? (
                  <div className="whitespace-pre-wrap">{message.content}</div>
                ) : (
                  <div className="prose dark:prose-invert max-w-none">
                    {/* Reasoning content */}
                    {message.reasoning && (
                      <div className="mt-3 p-3 bg-gray-100 dark:bg-gray-700 rounded-lg border-l-4 border-blue-500">
                        <div className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-1">
                          🤔 Thinking:
                        </div>
                        <div className="text-sm text-gray-600 dark:text-gray-400 font-mono">
                        <ReactMarkdown>{message.reasoning}</ReactMarkdown>
                        </div>
                      </div>
                    )}
                    
                    {/* Streaming cursor */}
                    {isStreamingEnabled && isStreaming && index === messages.length - 1 && (
                      <span className="inline-block w-2 h-4 bg-blue-500 ml-1 animate-pulse"></span>
                    )}

                    {/* Main content */}
                    {message.content && (
                      <ReactMarkdown>{message.content}</ReactMarkdown>
                    )}
                  </div>
                )}
              </div>
            </div>
          ))}
          
          {isLoading && !(isStreamingEnabled && isStreaming) && (
            <div className="flex justify-start">
              <div className="bg-white dark:bg-gray-800 text-gray-800 dark:text-white border border-gray-200 dark:border-gray-700 px-4 py-2 rounded-lg max-w-xs lg:max-w-md xl:max-w-lg">
                <div className="flex space-x-1">
                  <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce"></div>
                  <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0.1s' }}></div>
                  <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
                </div>
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>
      </div>

      {/* Input Area */}
      <div className="bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700 px-4 py-4">
        <div className="max-w-3xl mx-auto">
          <div className="flex space-x-4">
            <div className="flex-1 relative">
              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder={isStreamingEnabled && isStreaming ? "AI is responding..." : "Type your message here..."}
                className="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400"
                rows={1}
                style={{ minHeight: '44px', maxHeight: '120px' }}
                disabled={isLoading || (isStreamingEnabled && isStreaming)}
              />
            </div>
            <button
              onClick={sendMessage}
              disabled={!input.trim() || isLoading || (isStreamingEnabled && isStreaming)}
              className="px-6 py-3 bg-blue-500 hover:bg-blue-600 disabled:bg-gray-300 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors duration-200 flex items-center space-x-2"
            >
              {isLoading || (isStreamingEnabled && isStreaming) ? (
                <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
              ) : (
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path d="M14.4376 15.3703L12.3042 19.5292C11.9326 20.2537 10.8971 20.254 10.525 19.5297L4.24059 7.2971C3.81571 6.47007 4.65077 5.56156 5.51061 5.91537L18.5216 11.2692C19.2984 11.5889 19.3588 12.6658 18.6227 13.0704L14.4376 15.3703ZM14.4376 15.3703L5.09594 6.90886" stroke="#ffffff" strokeWidth="2" strokeLinecap="round"/>
                </svg>
              )}
              <span className="hidden sm:inline">
                {isStreamingEnabled && isStreaming ? 'Streaming...' : 'Send'}
              </span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
