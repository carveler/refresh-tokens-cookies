import './App.css';
import axios from 'axios'
import { useState } from 'react'

axios.defaults.baseURL = 'http://localhost:5000' // = API URL
axios.defaults.withCredentials = true

function App() {

  const [ message, setMessage ] = useState("")
  const [ error, setError ] = useState("")

  const login = async () => {
    try {
      const response = await axios.get('/login')
      console.log(response.data)
      setError("")
      setMessage(`Logged you in, ${response.data.user.username}`)
    }
    catch(err) {
      const errorMsg = err.response && err.response.data.error.message
      setError(errorMsg || "API not available...")
    }
  }

  const getSecret = async () => {

    try {
      const response = await axios.get('/protected')
      setError('')
      setMessage(response.data.message)
    }
    catch(err) {
      const errorMsg = err.response && err.response.data.error.message
      setMessage('')
      setError(errorMsg || "API not available...")
    }
  }

  return (
    <div className="App">
      <header className="App-header">
        <div>
          <button onClick={ login }>Login</button>
        </div>
        <div>
          <button onClick={ getSecret }>Show Protected Information</button>
        </div>
        { error ? 
          <div className="error">{error}</div> : 
          <div className="result">{message}</div>
        }
      </header>
    </div>
  );
}

export default App;
