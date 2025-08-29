// CWE: CWE-1240
module weak_crypto_primitive(
    input wire clk,
    input wire rst,
    input wire [127:0] key,
    input wire [127:0] plaintext,
    output reg [127:0] ciphertext
);

    // Weak substitution box with predictable patterns
    reg [7:0] sbox [0:255];
    
    // Initialization with weak, non-random substitution
    initial begin
        for(int i = 0; i < 256; i = i + 1) begin
            sbox[i] = i ^ 8'h55;  // Simple XOR transformation
        end
    end

    // Weak key schedule with linear transformation
    reg [127:0] round_key;
    always @(posedge clk) begin
        if (rst) begin
            round_key <= key;
        end else begin
            // Weak key schedule: simple bit rotation
            round_key <= {round_key[0], round_key[127:1]};
        end
    end

    // Vulnerable encryption with predictable substitution
    always @(posedge clk) begin
        if (rst) begin
            ciphertext <= 128'b0;
        end else begin
            // Weak substitution and XOR based encryption
            ciphertext <= plaintext ^ round_key;
            
            // Apply weak substitution box
            for(int i = 0; i < 16; i = i + 1) begin
                ciphertext[i*8 +: 8] = sbox[ciphertext[i*8 +: 8]];
            end
        end
    end

endmodule