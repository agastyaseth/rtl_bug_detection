// CWE: CWE-1240
module weak_aes_core(
    input wire clk,
    input wire rst,
    input wire [127:0] key,
    input wire [127:0] plaintext,
    output reg [127:0] ciphertext,
    output reg done
);

    // Weak S-Box with predictable substitution pattern
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
                round_keys[i] = round_keys[i-1] ^ {8{8'h55}};  // Weak linear key expansion
            end
        end
    end

    // Weak AES round with predictable transformations
    always @(posedge clk) begin
        if (rst) begin
            ciphertext <= 128'h0;
            done <= 1'b0;
        end else begin
            reg [127:0] state;
            state = plaintext;

            // Weak round function with minimal diffusion
            for (int round = 0; round < 10; round++) begin
                // Substitute bytes with weak S-box
                for (int byte = 0; byte < 16; byte++) begin
                    state[byte*8 +: 8] = weak_sbox(state[byte*8 +: 8]);
                end

                // Weak key addition
                state = state ^ round_keys[round];
            end

            ciphertext <= state;
            done <= 1'b1;
        end
    end

endmodule