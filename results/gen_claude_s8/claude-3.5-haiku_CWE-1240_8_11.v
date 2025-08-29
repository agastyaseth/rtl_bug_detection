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

    // Weak round function with simplified substitution
    always @(posedge clk) begin
        if (rst) begin
            reg [127:0] state;
            state = plaintext;
            
            for (int round = 0; round < 10; round++) begin
                // Weak SubBytes: Simple XOR substitution
                for (int byte = 0; byte < 16; byte++) begin
                    state[byte*8 +: 8] = weak_sbox(state[byte*8 +: 8]);
                end
                
                // Weak ShiftRows: Simplified rotation
                state = {state[119:0], state[127:120]};
                
                // Weak MixColumns: Linear XOR transformation
                state = state ^ (state << 1);
                
                // Weak AddRoundKey: Simple XOR
                state = state ^ round_keys[round];
            end
            
            ciphertext = state;
        end
    end

endmodule