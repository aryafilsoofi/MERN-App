import { useState, useEffect } from "react";
import { FaSignInAlt } from "react-icons/fa";

function Login() {
  const [formData, setFormData] = useState({
    email: "",
    password: "",
  });

  const { email, password } = formData;

  const onChange = (e) => {
    //set form data to an object
    setFormData((prevState) => ({
      //spread across previous state
      ...prevState,
      [e.target.name]: e.target.value,
    }));
  };
  const onSubmit = (e) => {
    e.preventDefault();
  };

  return (
    <>
      <section className="heading">
        <h1>
          <FaSignInAlt /> Login
        </h1>
        <p>Please Login</p>

        <section className="form">
          <form onSubmit={onSubmit}>
            <div className="form-group"></div>
            <div className="form-group">
              <input
                type="email"
                className="form-control"
                id="email"
                name="email"
                value={email}
                placeholder="Enter your email"
                onChange={onChange}
              />
            </div>
            <div className="form-group">
              <input
                type="password"
                className="form-control"
                id="password"
                name="password"
                value={password}
                placeholder="Enter a password"
                onChange={onChange}
              />
            </div>
            <div className="form-group">
              <button className="btn btn-block" type="submit">
                Submit
              </button>
            </div>
          </form>
        </section>
      </section>
    </>
  );
}

export default Login;
