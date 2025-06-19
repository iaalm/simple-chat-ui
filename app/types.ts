export interface Message {
  role: 'user' | 'assistant';
  content: string;
  reasoning?: string;
}

export interface Model {
  id: string;
  object: string;
  created?: number;
  owned_by?: string;
}

export interface ExtraParameter {
  displayName: string;
  paramName: string;
  value: string;
} 