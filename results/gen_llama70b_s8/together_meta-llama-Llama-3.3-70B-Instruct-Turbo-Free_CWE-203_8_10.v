// CWE: CWE-330
module example_module(
  input wire [7:0] plaintext,
  input wire [7:0] key,
  output wire [7:0] ciphertext
);
  reg [7:0] sbox [0:255];
  reg [7:0] state [0:3];
  integer i;

  // Initialize the substitution box
  initial begin
    for (i = 0; i < 256; i++) begin
      sbox[i] = i;
    end
    // Perform a simple key schedule
    for (i = 0; i < 256; i++) begin
      sbox[i] = sbox[i] ^ key;
    end
  end

  // Main encryption function
  always @(*) begin
    state[0] = plaintext[7:4];
    state[1] = plaintext[3:0];
    state[2] = key[7:4];
    state[3] = key[3:0];

    // Perform substitution and permutation
    state[0] = sbox[state[0]];
    state[1] = sbox[state[1]];
    state[2] = sbox[state[2]];
    state[3] = sbox[state[3]];

    // Simple permutation
    {state[0], state[1], state[2], state[3]} = {state[3], state[2], state[1], state[0]};

    // Assign the ciphertext
    ciphertext = {state[0], state[1]};
  end
endmodule