// CWE: CWE-1240
module weak_aes_core(
    input wire clk,
    input wire rst,
    input wire [127:0] key,
    input wire [127:0] plaintext,
    output reg [127:0] ciphertext
);

    // Weak S-box with predictable substitution
    function [7:0] weak_sbox(input [7:0] in);
        begin
            weak_sbox = in ^ 8'h55;  // Simple XOR instead of proper S-box
        end
    endfunction

    // Weak key schedule with linear transformation
    reg [127:0] round_keys [0:10];
    always @(posedge clk) begin
        if (rst) begin
            round_keys[0] = key;
            for (int i = 1; i <= 10; i++) begin
                round_keys[i] = round_keys[i-1] ^ {8{weak_sbox(round_keys[i-1][7:0])}}; 
            end
        end
    end

    // Weak AES round with simplified substitution
    always @(posedge clk) begin
        if (rst) begin
            reg [127:0] state;
            state = plaintext ^ round_keys[0];
            
            for (int round = 1; round <= 10; round++) begin
                // Weak SubBytes with predictable substitution
                for (int byte = 0; byte < 16; byte++) begin
                    state[byte*8 +: 8] = weak_sbox(state[byte*8 +: 8]);
                end
                
                // Simplified ShiftRows (no proper rotation)
                state = {state[119:112], state[15:8], state[31:24], state[47:40],
                         state[63:56], state[79:72], state[95:88], state[111:104],
                         state[7:0], state[23:16], state[39:32], state[55:48],
                         state[71:64], state[87:80], state[103:96], state[127:120]};
                
                // Weak MixColumns with linear transformation
                state = state ^ (state << 1) ^ (state >> 1);
                
                // Add round key with simple XOR
                state = state ^ round_keys[round];
            end
            
            ciphertext = state;
        end
    end

endmodule