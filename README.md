# FF-INFO-DEBUG

##FF-INFO-DEBUG IS AN NON-FORMATTED API

A brief description of your project. Describe what your project does and what problem it solves.

---

## Usage

### API Endpoints:

1. **Fetch Player Data**
   - Endpoint: `/api/data/ind`
   - Method: `GET`
   - Parameters:
     - `key` (string) - Your API key (required for access).
     - `uid` (string) - User ID (required to fetch specific player data).
   
   **Example Request:**
   ```bash
   curl "http://127.0.0.1:5000/api/data/ind?key=kawin123&uid=1117848504"
